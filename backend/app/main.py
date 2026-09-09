from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.agents.auto_fix_agent import generate_fix
from app.agents.validation_agent import run_validation_agent
from app.config import settings
from app.database import Base, engine
from app.risk_engine import (
    assess_findings,
    calculate_overall_risk,
)
from app.scanner import (
    cleanup_temp,
    extract_zip_to_temp,
    run_semgrep_scan,
)
from app.services.code_context import get_code_context


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title=(
        "A Multi-Agent System for Automated "
        "Software Repository Security Analysis"
    ),
    description=(
        "Automated software repository security analysis "
        "using Semgrep, risk assessment, AI-assisted "
        "remediation and validation."
    ),
    version="4.0.0",
)


# ============================================================
# DATABASE
# ============================================================

try:
    Base.metadata.create_all(
        bind=engine
    )
except Exception as exc:
    print(
        f"Database initialization warning: {exc}"
    )


# ============================================================
# CORS
# ============================================================

default_origins = [
    "https://sentinelforge-ai.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000",
]

configured_origins = getattr(
    settings,
    "cors_origins",
    None,
)

if isinstance(
    configured_origins,
    list,
):
    allowed_origins = list(
        dict.fromkeys(
            default_origins + configured_origins
        )
    )
else:
    allowed_origins = default_origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=(
        r"https://sentinelforge.*\.vercel\.app"
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LIMITS
# ============================================================

MAX_UPLOAD_SIZE = 50 * 1024 * 1024

# Maximum number of UNIQUE source files sent to Groq.
MAX_AUTO_FIXES = 3

MAX_SOURCE_FILE_SIZE = 10 * 1024 * 1024


# ============================================================
# HELPERS
# ============================================================

def normalize_role(
    role: str,
) -> str:
    """
    Validate and normalize user role.
    """

    value = str(
        role or ""
    ).strip().lower()

    if value not in {
        "student",
        "developer",
    }:
        raise ValueError(
            "Role must be either 'student' or 'developer'."
        )

    return value


def validate_email(
    email: str,
) -> str:
    """
    Basic email validation.
    """

    value = str(
        email or ""
    ).strip()

    if not value:
        raise ValueError(
            "Email address is required."
        )

    if "@" not in value:
        raise ValueError(
            "Invalid email address."
        )

    return value


def get_finding_line(
    finding: dict[str, Any],
) -> int | None:
    """
    Safely get finding line number.
    """

    start = finding.get(
        "start",
        {},
    )

    if isinstance(
        start,
        dict,
    ):
        line = start.get(
            "line"
        )

        if isinstance(
            line,
            int,
        ):
            return line

        try:
            return int(line)
        except (
            TypeError,
            ValueError,
        ):
            pass

    line = finding.get(
        "line"
    )

    if isinstance(
        line,
        int,
    ):
        return line

    try:
        return int(line)
    except (
        TypeError,
        ValueError,
    ):
        return None


def safe_finding_copy(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert finding into JSON-safe data.
    """

    try:
        return json.loads(
            json.dumps(
                finding,
                default=str,
            )
        )

    except Exception:

        return {
            "check_id": finding.get(
                "check_id",
                "unknown",
            ),
            "path": finding.get(
                "path",
                "unknown",
            ),
            "start": finding.get(
                "start",
                {},
            ),
            "extra": finding.get(
                "extra",
                {},
            ),
        }


def build_stage(
    stage_id: str,
    title: str,
    status: str,
    message: str = "",
) -> dict[str, str]:
    """
    Build a frontend-friendly stage object.
    """

    return {
        "id": stage_id,
        "title": title,
        "status": status,
        "message": message,
    }


def resolve_repository_path(
    extract_dir: str | Path,
    source_path: str,
) -> Path:
    """
    Resolve relative or absolute Semgrep path safely.

    Supports:

        project/app.py

    and:

        /tmp/.../extracted/project/app.py
    """

    root = Path(
        extract_dir
    ).resolve()

    raw_path = Path(
        str(source_path)
    )

    if raw_path.is_absolute():

        target = raw_path.resolve()

    else:

        target = (
            root / raw_path
        ).resolve()

    try:

        target.relative_to(
            root
        )

    except ValueError as exc:

        raise ValueError(
            "Source path is outside the extracted repository."
        ) from exc

    return target


def normalize_repository_path(
    extract_dir: str | Path,
    source_path: str,
) -> str:
    """
    Convert Semgrep absolute path into repository-relative path.
    """

    root = Path(
        extract_dir
    ).resolve()

    target = resolve_repository_path(
        extract_dir,
        source_path,
    )

    relative = target.relative_to(
        root
    )

    return relative.as_posix()


def read_complete_source_file(
    extract_dir: str | Path,
    repository_path: str,
) -> str:
    """
    Read complete source file for Auto-Fix.
    """

    target = resolve_repository_path(
        extract_dir,
        repository_path,
    )

    if not target.exists():

        raise FileNotFoundError(
            f"Source file not found: {repository_path}"
        )

    if not target.is_file():

        raise ValueError(
            f"Source path is not a file: {repository_path}"
        )

    if (
        target.stat().st_size
        > MAX_SOURCE_FILE_SIZE
    ):

        raise ValueError(
            "Source file is too large for AI Auto-Fix."
        )

    return target.read_text(
        encoding="utf-8",
        errors="replace",
    )


def group_findings_by_file(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Group Semgrep findings by repository file.

    Example:

        app.py
          -> finding 1
          -> finding 2
          -> finding 3

    The first finding becomes the main finding and the
    remaining findings are attached through
    `related_findings`.

    This allows ONE Groq call per unique file.
    """

    groups: dict[str, list[dict[str, Any]]] = {}

    path_order: list[str] = []


    for finding in findings:

        path = str(
            finding.get(
                "path",
                "",
            )
        ).strip()

        if not path:
            continue

        normalized_path = (
            path.replace(
                "\\",
                "/",
            )
        )

        key = normalized_path.lower()

        if key not in groups:

            groups[key] = []

            path_order.append(
                key
            )

        groups[key].append(
            finding
        )


    grouped = []


    for key in path_order:

        file_findings = groups[key]

        primary = safe_finding_copy(
            file_findings[0]
        )

        primary[
            "related_findings"
        ] = [
            safe_finding_copy(
                item
            )
            for item in file_findings
        ]

        primary[
            "finding_count_for_file"
        ] = len(
            file_findings
        )

        grouped.append(
            primary
        )


    return grouped


def clean_fix_result_for_response(
    fix: dict[str, Any],
) -> dict[str, Any]:
    """
    Keep Auto-Fix response JSON-safe.
    """

    return {
        "success": bool(
            fix.get(
                "success",
                False,
            )
        ),
        "finding_index": fix.get(
            "finding_index",
            0,
        ),
        "original_path": fix.get(
            "original_path",
            "",
        ),
        "filename": fix.get(
            "filename",
            None,
        ),
        "fixed_code": fix.get(
            "fixed_code",
            None,
        ),
        "error": fix.get(
            "error",
            None,
        ),
    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "success": True,
        "service": (
            "A Multi-Agent System for Automated "
            "Software Repository Security Analysis"
        ),
        "version": "4.0.0",
        "message": (
            "Security analysis backend is running."
        ),
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": "sentinelforge-ai-backend",
        "environment": getattr(
            settings,
            "environment",
            "development",
        ),
        "version": "4.0.0",
    }


# ============================================================
# MASTER AUTONOMOUS SCAN
# ============================================================

@app.post("/scan/start")
async def start_autonomous_scan(
    role: str = Form(...),
    email: str = Form(...),
    file: UploadFile = File(...),
):

    """
    FINAL AUTONOMOUS SECURITY PIPELINE

        Repository
             ↓
        Extraction
             ↓
        Semgrep
             ↓
        Risk Assessment
             ↓
        AI Auto-Fix
             ↓
        Validation Agent
             ↓
        Final Results

    Groq is used ONLY for Auto-Fix.

    Same source file with multiple Semgrep findings
    receives ONE Groq Auto-Fix call.

    Maximum UNIQUE files sent to Groq = 3.

    No second Semgrep scan is performed.
    """

    # ========================================================
    # VALIDATE INPUT
    # ========================================================

    try:

        normalized_role = normalize_role(
            role
        )

        normalized_email = validate_email(
            email
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail=(
                "Repository ZIP file is required."
            ),
        )


    original_filename = Path(
        file.filename
    ).name


    if not original_filename.lower().endswith(
        ".zip"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Only ZIP repository files are supported."
            ),
        )


    # ========================================================
    # PIPELINE STAGES
    # ========================================================

    stages = [

        build_stage(
            "repository",
            "Repository Received",
            "completed",
            "Repository ZIP received successfully.",
        ),

        build_stage(
            "extract",
            "Repository Extraction",
            "pending",
        ),

        build_stage(
            "semgrep",
            "Security Detection",
            "pending",
        ),

        build_stage(
            "risk",
            "Risk Assessment",
            "pending",
        ),

        build_stage(
            "fix",
            "AI Auto-Fix",
            "pending",
        ),

        build_stage(
            "validation",
            "Validation Agent",
            "pending",
        ),
    ]


    extract_dir = None


    try:

        # ====================================================
        # READ UPLOAD
        # ====================================================

        contents = await file.read()


        if not contents:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Uploaded ZIP file is empty."
                ),
            )


        if len(contents) > MAX_UPLOAD_SIZE:

            raise HTTPException(
                status_code=413,
                detail=(
                    "Repository ZIP exceeds the "
                    "50 MB upload limit."
                ),
            )


        # ====================================================
        # ZIP VALIDATION
        # ====================================================

        try:

            with zipfile.ZipFile(
                io.BytesIO(contents)
            ) as archive:

                if archive.testzip() is not None:

                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Uploaded ZIP archive "
                            "is corrupted."
                        ),
                    )

        except zipfile.BadZipFile as exc:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Uploaded file is not a valid ZIP archive."
                ),
            ) from exc


        # ====================================================
        # EXTRACTION
        # ====================================================

        stages[1] = build_stage(
            "extract",
            "Repository Extraction",
            "running",
            "Safely extracting repository contents.",
        )


        extract_dir = extract_zip_to_temp(
            contents
        )


        stages[1] = build_stage(
            "extract",
            "Repository Extraction",
            "completed",
            "Repository extracted successfully.",
        )


        # ====================================================
        # SEMGREP
        # ====================================================

        stages[2] = build_stage(
            "semgrep",
            "Security Detection",
            "running",
            (
                "Semgrep is scanning the repository "
                "for vulnerabilities."
            ),
        )


        raw_findings = run_semgrep_scan(
            extract_dir
        )


        if not isinstance(
            raw_findings,
            list,
        ):
            raw_findings = []


        findings = []


        # ====================================================
        # NORMALIZE FINDING PATHS
        # ====================================================

        for raw_finding in raw_findings:

            if not isinstance(
                raw_finding,
                dict,
            ):
                continue


            finding = safe_finding_copy(
                raw_finding
            )


            raw_path = str(
                finding.get(
                    "path",
                    "",
                )
            ).strip()


            if raw_path:

                try:

                    repository_path = (
                        normalize_repository_path(
                            extract_dir,
                            raw_path,
                        )
                    )

                    finding[
                        "path"
                    ] = repository_path

                except Exception as exc:

                    print(
                        "Path normalization warning:",
                        exc,
                    )

                    # Ignore an invalid path instead of
                    # exposing the temporary filesystem path.
                    finding[
                        "path"
                    ] = ""


            findings.append(
                finding
            )


        # ====================================================
        # ADD SOURCE CONTEXT
        # ====================================================

        for finding in findings:

            repository_path = str(
                finding.get(
                    "path",
                    "",
                )
            ).strip()


            line = get_finding_line(
                finding
            )


            source_context = ""


            if repository_path and line:

                try:

                    source_context = (
                        get_code_context(
                            extract_dir,
                            repository_path,
                            line,
                        )
                    )

                except Exception as exc:

                    print(
                        "Source context warning:",
                        exc,
                    )


            finding[
                "source_code"
            ] = source_context


        stages[2] = build_stage(
            "semgrep",
            "Security Detection",
            "completed",
            (
                f"{len(findings)} "
                "security finding(s) detected."
            ),
        )


        # ====================================================
        # RISK ASSESSMENT
        # ====================================================

        stages[3] = build_stage(
            "risk",
            "Risk Assessment",
            "running",
            (
                "Calculating vulnerability severity "
                "and risk levels."
            ),
        )


        try:

            risk_assessments = assess_findings(
                findings
            )

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    "Risk assessment failed: "
                    f"{exc}"
                ),
            ) from exc


        try:

            overall_risk = calculate_overall_risk(
                risk_assessments
            )

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    "Overall risk calculation failed: "
                    f"{exc}"
                ),
            ) from exc


        if not isinstance(
            risk_assessments,
            list,
        ):
            risk_assessments = []


        if not isinstance(
            overall_risk,
            dict,
        ):
            overall_risk = {}


        stages[3] = build_stage(
            "risk",
            "Risk Assessment",
            "completed",
            (
                "Risk assessment completed."
            ),
        )


        # ====================================================
        # GROUP FINDINGS BY SOURCE FILE
        # ====================================================

        grouped_findings = (
            group_findings_by_file(
                findings
            )
        )


        # ====================================================
        # GROQ AUTO-FIX
        # ====================================================

        stages[4] = build_stage(
            "fix",
            "AI Auto-Fix",
            "running",
            (
                "Preparing corrected copies for "
                "vulnerable source files."
            ),
        )


        fixes = []


        if not grouped_findings:

            stages[4] = build_stage(
                "fix",
                "AI Auto-Fix",
                "skipped",
                (
                    "No vulnerable source files "
                    "require remediation."
                ),
            )

        else:

            # Only first 3 UNIQUE source files are sent to
            # Groq. Duplicate findings in the same file are
            # combined into one Auto-Fix request.
            files_to_fix = grouped_findings[
                :MAX_AUTO_FIXES
            ]


            for index, grouped_finding in enumerate(
                files_to_fix
            ):

                repository_path = str(
                    grouped_finding.get(
                        "path",
                        "",
                    )
                ).strip()


                fix_result = {

                    "success": False,

                    "finding_index": index,

                    "original_path": repository_path,

                    "filename": (
                        Path(
                            repository_path
                        ).name
                        if repository_path
                        else None
                    ),

                    "fixed_code": None,

                    "error": None,
                }


                if not repository_path:

                    fix_result[
                        "error"
                    ] = (
                        "Finding does not contain "
                        "a valid repository path."
                    )

                    fixes.append(
                        fix_result
                    )

                    continue


                # ============================================
                # READ COMPLETE SOURCE FILE
                # ============================================

                try:

                    full_source_code = (
                        read_complete_source_file(
                            extract_dir,
                            repository_path,
                        )
                    )

                except Exception as exc:

                    print(
                        f"Source read error for "
                        f"{repository_path}:",
                        exc,
                    )

                    fix_result[
                        "error"
                    ] = str(exc)

                    fixes.append(
                        fix_result
                    )

                    continue


                # ============================================
                # PREPARE VULNERABILITY DATA
                # ============================================

                vulnerability_for_ai = (
                    safe_finding_copy(
                        grouped_finding
                    )
                )


                vulnerability_for_ai[
                    "path"
                ] = repository_path


                # ============================================
                # ONE GROQ CALL FOR THIS FILE
                # ============================================

                try:

                    fixed_code = generate_fix(
                        vulnerability=(
                            vulnerability_for_ai
                        ),
                        source_code=(
                            full_source_code
                        ),
                    )


                    if not isinstance(
                        fixed_code,
                        str,
                    ):

                        raise ValueError(
                            "AI Auto-Fix returned invalid code."
                        )


                    fixed_code = fixed_code.strip()


                    if not fixed_code:

                        raise ValueError(
                            "AI Auto-Fix returned empty code."
                        )


                    fix_result[
                        "success"
                    ] = True


                    fix_result[
                        "fixed_code"
                    ] = fixed_code


                except Exception as exc:

                    print(
                        f"Auto-Fix error for "
                        f"{repository_path}:",
                        exc,
                    )

                    fix_result[
                        "error"
                    ] = str(exc)


                fixes.append(
                    clean_fix_result_for_response(
                        fix_result
                    )
                )


            # ------------------------------------------------
            # MARK REMAINING UNIQUE FILES AS SKIPPED
            # ------------------------------------------------

            if len(grouped_findings) > MAX_AUTO_FIXES:

                for skipped_group in grouped_findings[
                    MAX_AUTO_FIXES:
                ]:

                    skipped_path = str(
                        skipped_group.get(
                            "path",
                            "",
                        )
                    ).strip()


                    fixes.append(
                        {
                            "success": False,

                            "finding_index": (
                                -1
                            ),

                            "original_path": (
                                skipped_path
                            ),

                            "filename": (
                                Path(
                                    skipped_path
                                ).name
                                if skipped_path
                                else None
                            ),

                            "fixed_code": None,

                            "error": (
                                "Auto-Fix skipped because "
                                f"the maximum of {MAX_AUTO_FIXES} "
                                "unique files was reached."
                            ),
                        }
                    )


            successful_fixes = sum(
                1
                for fix in fixes
                if fix.get(
                    "success",
                    False,
                )
            )


            unavailable_fixes = (
                len(fixes)
                - successful_fixes
            )


            stages[4] = build_stage(
                "fix",
                "AI Auto-Fix",
                "completed",
                (
                    f"{successful_fixes} unique file(s) "
                    f"fixed; {unavailable_fixes} unavailable."
                ),
            )


        # ====================================================
        # VALIDATION AGENT
        # ====================================================

        stages[5] = build_stage(
            "validation",
            "Validation Agent",
            "running",
            (
                "Checking generated remediation artifacts."
            ),
        )


        try:

            validation_result = (
                run_validation_agent(
                    fixes
                )
            )

        except Exception as exc:

            print(
                "Validation Agent error:",
                exc,
            )


            validation_result = {

                "success": False,

                "status": "attention",

                "message": (
                    "Validation Agent could not "
                    "complete artifact checks."
                ),

                "results": [],

                "total_artifacts": len(
                    fixes
                ),

                "ready_artifacts": 0,

                "attention_artifacts": len(
                    fixes
                ),

                "security_scan_performed": False,

                "second_semgrep_scan": False,

                "findings_modified": False,

                "risk_modified": False,

                "security_verified": False,
            }


        ready_artifacts = validation_result.get(
            "ready_artifacts",
            0,
        )


        validation_status = (
            "Validation Agent completed remediation "
            "artifact checks."
        )


        stages[5] = build_stage(
            "validation",
            "Validation Agent",
            "completed",
            (
                f"{ready_artifacts} remediation "
                "artifact(s) ready for output."
            ),
        )


        # ====================================================
        # FINAL RESPONSE
        # ====================================================

        return {

            "success": True,

            "filename": original_filename,

            "role": normalized_role,

            "email": normalized_email,

            "findings_count": len(
                findings
            ),

            "findings": findings,

            "risk_assessments": (
                risk_assessments
            ),

            "overall_risk": overall_risk,

            # No AI report generation.
            "ai_analysis": "",

            "fixes": fixes,

            "validation": validation_result,

            "validation_status": validation_status,

            "pipeline_status": "completed",

            "stages": stages,

            "max_auto_fixes": (
                MAX_AUTO_FIXES
            ),

            "unique_vulnerable_files": (
                len(grouped_findings)
            ),

            "auto_fix_files_attempted": min(
                len(grouped_findings),
                MAX_AUTO_FIXES,
            ),

            "auto_fix_successful": (
                successful_fixes
                if grouped_findings
                else 0
            ),

            "groq_used_for_report": False,

            "groq_used_for_auto_fix": True,

            "second_scan_after_fix": False,

            "original_repository_modified": False,

            "message": (
                "Autonomous repository security "
                "analysis completed."
            ),
        }


    except HTTPException:

        raise


    except Exception as exc:

        print(
            "Autonomous scan error:",
            exc,
        )


        raise HTTPException(
            status_code=500,
            detail=(
                "Autonomous security analysis failed: "
                f"{exc}"
            ),
        ) from exc


    finally:

        # ====================================================
        # CLEAN TEMPORARY FILES
        # ====================================================

        if extract_dir:

            try:

                cleanup_temp(
                    extract_dir
                )

            except Exception as exc:

                print(
                    "Cleanup warning:",
                    exc,
                )


# ============================================================
# LEGACY SCAN ENDPOINT
# ============================================================

@app.post("/scan/upload")
async def upload_and_scan(
    file: UploadFile = File(...),
):

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail=(
                "Repository ZIP file is required."
            ),
        )


    filename = Path(
        file.filename
    ).name


    if not filename.lower().endswith(
        ".zip"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Only ZIP repository files are supported."
            ),
        )


    extract_dir = None


    try:

        contents = await file.read()


        if not contents:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Uploaded ZIP file is empty."
                ),
            )


        if len(contents) > MAX_UPLOAD_SIZE:

            raise HTTPException(
                status_code=413,
                detail=(
                    "Repository ZIP exceeds the "
                    "50 MB upload limit."
                ),
            )


        extract_dir = extract_zip_to_temp(
            contents
        )


        raw_findings = run_semgrep_scan(
            extract_dir
        )


        if not isinstance(
            raw_findings,
            list,
        ):
            raw_findings = []


        findings = []


        for raw_finding in raw_findings:

            if not isinstance(
                raw_finding,
                dict,
            ):
                continue


            current = safe_finding_copy(
                raw_finding
            )


            raw_path = str(
                current.get(
                    "path",
                    "",
                )
            ).strip()


            if raw_path:

                try:

                    current[
                        "path"
                    ] = normalize_repository_path(
                        extract_dir,
                        raw_path,
                    )

                except Exception:

                    current[
                        "path"
                    ] = ""


            findings.append(
                current
            )


        risk_assessments = assess_findings(
            findings
        )


        overall_risk = calculate_overall_risk(
            risk_assessments
        )


        return {

            "success": True,

            "filename": filename,

            "findings_count": len(
                findings
            ),

            "findings": findings,

            "risk_assessments": (
                risk_assessments
            ),

            "overall_risk": overall_risk,
        }


    except HTTPException:

        raise


    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Repository scan failed: "
                f"{exc}"
            ),
        ) from exc


    finally:

        if extract_dir:

            try:

                cleanup_temp(
                    extract_dir
                )

            except Exception:

                pass


# ============================================================
# PHASE 4 INFORMATION
# ============================================================

@app.get("/phase4")
async def phase4_info():

    return {

        "success": True,

        "title": (
            "A Multi-Agent System for Automated "
            "Software Repository Security Analysis"
        ),

        "architecture": [
            "Repository Upload",
            "Safe ZIP Extraction",
            "Semgrep Security Detection",
            "Risk Assessment",
            "AI Auto-Fix",
            "Validation Agent",
            "Role-Based Reporting",
            "Automatic Email Delivery",
            "Manual Security Report Download",
            "Manual Fixed Repository Download",
        ],

        "groq_used_for_report": False,

        "groq_used_for_auto_fix": True,

        "max_unique_files_for_auto_fix": (
            MAX_AUTO_FIXES
        ),

        "second_scan_after_fix": False,

        "original_repository_modified": False,
    }