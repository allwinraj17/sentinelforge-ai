from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.agents.auto_fix_agent import generate_fix
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


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="A Multi-Agent System for Automated Software Repository Security Analysis",
    description=(
        "Autonomous software repository security analysis "
        "using Semgrep, risk assessment and AI-assisted "
        "vulnerability remediation."
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

    # Supports Vercel preview URLs such as:
    # https://sentinelforge-njrf0j0l9-aaa-ac6c.vercel.app
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

# Groq is used ONLY for Auto-Fix.
# Limiting the number of AI fixes keeps the workflow
# faster and reduces token consumption.
MAX_AUTO_FIXES = 3

# Prevent very large source files from being passed
# to the Auto-Fix model.
MAX_SOURCE_FILE_SIZE = 10 * 1024 * 1024


# ============================================================
# HELPERS
# ============================================================

def normalize_role(
    role: str,
) -> str:
    """
    Normalize and validate user role.
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
    Validate email input.
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
    Safely extract a finding line number.
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
    Convert scanner output into JSON-safe data.
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
    Build a frontend-friendly pipeline stage.
    """

    return {
        "id": stage_id,
        "title": title,
        "status": status,
        "message": message,
    }


def read_complete_source_file(
    extract_dir: str | Path,
    relative_path: str,
) -> str:
    """
    Read the complete file from the extracted repository.

    Auto-Fix receives the complete source file so that the
    AI can return a complete corrected replacement file.
    """

    root = Path(
        extract_dir
    ).resolve()

    relative = Path(
        str(relative_path)
    )

    if relative.is_absolute():
        raise ValueError(
            "Absolute source paths are not allowed."
        )

    target = (
        root / relative
    ).resolve()

    try:
        target.relative_to(
            root
        )
    except ValueError as exc:
        raise ValueError(
            "Source path is outside the repository."
        ) from exc

    if not target.exists():
        raise FileNotFoundError(
            f"Source file not found: {relative_path}"
        )

    if not target.is_file():
        raise ValueError(
            f"Source path is not a file: {relative_path}"
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
# PHASE 4 MASTER PIPELINE
# ============================================================

@app.post("/scan/start")
async def start_autonomous_scan(
    role: str = Form(...),
    email: str = Form(...),
    file: UploadFile = File(...),
):
    """
    Phase 4 master security pipeline.

    FINAL FLOW:

        Repository
            ↓
        Safe Extraction
            ↓
        Semgrep Detection
            ↓
        Risk Assessment
            ↓
        Groq AI Auto-Fix
            ↓
        Validation Preparation
            ↓
        Return Results

    Groq is NOT used for report generation.

    No second Semgrep scan is performed.

    Original repository is never modified.
    """

    # ========================================================
    # INPUT VALIDATION
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
    # INITIAL STAGES
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
            "Validation Preparation",
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
        # STAGE 1 - EXTRACTION
        # ====================================================

        stages[1] = build_stage(
            "extract",
            "Repository Extraction",
            "running",
            (
                "Safely extracting repository contents."
            ),
        )


        extract_dir = extract_zip_to_temp(
            contents
        )


        stages[1] = build_stage(
            "extract",
            "Repository Extraction",
            "completed",
            (
                "Repository extracted successfully."
            ),
        )


        # ====================================================
        # STAGE 2 - SEMGREP
        # ====================================================

        stages[2] = build_stage(
            "semgrep",
            "Security Detection",
            "running",
            (
                "Semgrep is scanning the repository "
                "for security vulnerabilities."
            ),
        )


        findings = run_semgrep_scan(
            extract_dir
        )


        if not isinstance(
            findings,
            list,
        ):
            findings = []


        safe_findings = []


        for finding in findings:

            if not isinstance(
                finding,
                dict,
            ):
                continue


            current_finding = safe_finding_copy(
                finding
            )


            path = current_finding.get(
                "path",
                "",
            )


            line = get_finding_line(
                current_finding
            )


            source_context = ""


            if path and line:

                try:

                    from app.services.code_context import (
                        get_code_context,
                    )

                    source_context = (
                        get_code_context(
                            extract_dir,
                            str(path),
                            line,
                        )
                    )

                except Exception as exc:

                    print(
                        "Source context warning:",
                        exc,
                    )


            current_finding[
                "source_code"
            ] = source_context


            safe_findings.append(
                current_finding
            )


        findings = safe_findings


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
        # STAGE 3 - RISK ASSESSMENT
        # ====================================================

        stages[3] = build_stage(
            "risk",
            "Risk Assessment",
            "running",
            (
                "Calculating severity and risk levels."
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
        # STAGE 4 - GROQ AUTO-FIX ONLY
        # ====================================================

        stages[4] = build_stage(
            "fix",
            "AI Auto-Fix",
            "running",
            (
                "AI is preparing corrected copies "
                "for high-priority findings."
            ),
        )


        fixes = []


        if not findings:

            stages[4] = build_stage(
                "fix",
                "AI Auto-Fix",
                "skipped",
                (
                    "No vulnerabilities require remediation."
                ),
            )

        else:

            findings_to_fix = findings[
                :MAX_AUTO_FIXES
            ]


            for index, finding in enumerate(
                findings_to_fix
            ):

                path = finding.get(
                    "path",
                    "",
                )


                fix_result = {

                    "success": False,

                    "finding_index": index,

                    "original_path": path,

                    "filename": (
                        Path(
                            str(path)
                        ).name
                        if path
                        else None
                    ),

                    "fixed_code": None,

                    "error": None,
                }


                if not path:

                    fix_result[
                        "error"
                    ] = (
                        "Finding does not contain "
                        "a file path."
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
                            str(path),
                        )
                    )

                except Exception as exc:

                    fix_result[
                        "error"
                    ] = str(exc)

                    fixes.append(
                        fix_result
                    )

                    continue


                # ============================================
                # GROQ CALL
                # ============================================

                try:

                    fixed_code = generate_fix(
                        vulnerability=finding,
                        source_code=full_source_code,
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
                        f"Auto-Fix error for {path}:",
                        exc,
                    )

                    fix_result[
                        "error"
                    ] = str(exc)


                fixes.append(
                    fix_result
                )


            # ================================================
            # REPORT SKIPPED FINDINGS
            # ================================================

            if len(findings) > MAX_AUTO_FIXES:

                for skipped_index in range(
                    MAX_AUTO_FIXES,
                    len(findings),
                ):

                    skipped_finding = findings[
                        skipped_index
                    ]

                    skipped_path = (
                        skipped_finding.get(
                            "path",
                            "",
                        )
                    )


                    fixes.append(
                        {
                            "success": False,

                            "finding_index": skipped_index,

                            "original_path": skipped_path,

                            "filename": (
                                Path(
                                    str(
                                        skipped_path
                                    )
                                ).name
                                if skipped_path
                                else None
                            ),

                            "fixed_code": None,

                            "error": (
                                "Auto-Fix skipped to "
                                "reduce AI usage and "
                                "processing time."
                            ),
                        }
                    )


            successful_fixes = sum(
                1
                for fix in fixes
                if fix.get(
                    "success"
                )
            )


            failed_or_skipped = (
                len(fixes)
                - successful_fixes
            )


            stages[4] = build_stage(
                "fix",
                "AI Auto-Fix",
                "completed",
                (
                    f"{successful_fixes} fix(es) generated; "
                    f"{failed_or_skipped} skipped/failed."
                ),
            )


        # ====================================================
        # STAGE 5 - VALIDATION PREPARATION
        # ====================================================

        stages[5] = build_stage(
            "validation",
            "Validation Preparation",
            "running",
            (
                "Preparing final remediation output."
            ),
        )


        validation_status = (
            "Validation preparation completed. "
            "No second security scan was performed."
        )


        stages[5] = build_stage(
            "validation",
            "Validation Preparation",
            "completed",
            validation_status,
        )


        # ====================================================
        # FINAL RESPONSE
        # ====================================================

        return {

            "success": True,

            "filename": original_filename,

            "role": normalized_role,

            "email": normalized_email,

            "findings_count": len(findings),

            "findings": findings,

            "risk_assessments": risk_assessments,

            "overall_risk": overall_risk,

            # No Groq report-generation result.
            "ai_analysis": "",

            "fixes": fixes,

            "validation_status": validation_status,

            "pipeline_status": "completed",

            "stages": stages,

            "max_auto_fixes": MAX_AUTO_FIXES,

            "groq_used_for_report": False,

            "groq_used_for_auto_fix": True,

            "second_scan_after_fix": False,

            "message": (
                "Autonomous security analysis completed."
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


        findings = run_semgrep_scan(
            extract_dir
        )


        if not isinstance(
            findings,
            list,
        ):
            findings = []


        risk_assessments = assess_findings(
            findings
        )


        overall_risk = calculate_overall_risk(
            risk_assessments
        )


        return {

            "success": True,

            "filename": filename,

            "findings_count": len(findings),

            "findings": findings,

            "risk_assessments": risk_assessments,

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

        "phase": "Phase 4",

        "title": (
            "A Multi-Agent System for Automated "
            "Software Repository Security Analysis"
        ),

        "features": [

            "Repository Upload",

            "Safe ZIP Extraction",

            "Semgrep Security Detection",

            "Risk Assessment",

            "Groq AI Auto-Fix",

            "Role-Based Reporting",

            "Manual Security Report Download",

            "Manual Fixed Repository Download",

            "Automatic Email Report",
        ],

        "groq_used_for_report": False,

        "groq_used_for_auto_fix": True,

        "max_auto_fixes": MAX_AUTO_FIXES,

        "second_scan_after_fix": False,

        "original_repository_modified": False,
    }