from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

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
from app.ai_service import analyze_security_findings
from app.agents.auto_fix_agent import generate_fix
from app.config import settings
from app.database import Base, engine


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="SentinelForge AI",
    description=(
        "Autonomous AI-powered repository security "
        "analysis and remediation platform."
    ),
    version="4.0.0",
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

try:
    Base.metadata.create_all(bind=engine)
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
    allow_origin_regex=r"https://sentinelforge.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# CONSTANTS
# ============================================================

MAX_UPLOAD_SIZE = 50 * 1024 * 1024


# ============================================================
# HELPERS
# ============================================================

def _normalize_role(role: str) -> str:
    """
    Normalize the user role.
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


def _validate_email(email: str) -> str:
    """
    Basic backend validation for email.
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


def _get_line_from_finding(
    finding: dict[str, Any],
) -> int | None:
    """
    Safely extract vulnerability line number.
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


def _safe_finding_copy(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert scanner output into a JSON-safe dictionary.
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
            "extra": finding.get(
                "extra",
                {},
            ),
        }


def _build_stage(
    stage_id: str,
    title: str,
    status: str,
    message: str,
) -> dict[str, str]:
    """
    Create a pipeline stage object.
    """

    return {
        "id": stage_id,
        "title": title,
        "status": status,
        "message": message,
    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "success": True,
        "service": "SentinelForge AI",
        "version": "4.0.0",
        "message": "SentinelForge AI backend is running.",
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
    SentinelForge AI Phase 4 autonomous security pipeline.

    Pipeline:

        Repository received
              ↓
        ZIP validation/extraction
              ↓
        Semgrep security scan
              ↓
        Risk assessment
              ↓
        Groq AI analysis
              ↓
        AI Auto-Fix
              ↓
        Validation preparation
              ↓
        Return complete results

    Important:
        Phase 4 does NOT run a second Semgrep scan
        after Auto-Fix generation.

    Original uploaded repository is never modified.
    """

    # ========================================================
    # INPUT VALIDATION
    # ========================================================

    try:

        normalized_role = _normalize_role(
            role
        )

        normalized_email = _validate_email(
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
            detail="Repository ZIP file is required.",
        )


    original_filename = Path(
        file.filename
    ).name


    if not original_filename.lower().endswith(
        ".zip"
    ):

        raise HTTPException(
            status_code=400,
            detail="Only ZIP repository files are supported.",
        )


    # ========================================================
    # INITIAL PIPELINE
    # ========================================================

    stages: list[dict[str, str]] = [

        _build_stage(
            "repository",
            "Repository Received",
            "completed",
            "Repository ZIP received successfully.",
        ),

        _build_stage(
            "extract",
            "Repository Extraction",
            "pending",
            "",
        ),

        _build_stage(
            "semgrep",
            "Security Detection",
            "pending",
            "",
        ),

        _build_stage(
            "risk",
            "Risk Assessment",
            "pending",
            "",
        ),

        _build_stage(
            "ai",
            "AI Security Analysis",
            "pending",
            "",
        ),

        _build_stage(
            "fix",
            "AI Auto-Fix",
            "pending",
            "",
        ),

        _build_stage(
            "validation",
            "Validation Preparation",
            "pending",
            "",
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
                detail="Uploaded ZIP file is empty.",
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
                        detail="Uploaded ZIP archive is corrupted.",
                    )

        except zipfile.BadZipFile as exc:

            raise HTTPException(
                status_code=400,
                detail="Uploaded file is not a valid ZIP archive.",
            ) from exc


        # ====================================================
        # EXTRACTION
        # ====================================================

        stages[1] = _build_stage(
            "extract",
            "Repository Extraction",
            "running",
            "Safely extracting repository contents.",
        )


        extract_dir = extract_zip_to_temp(
            contents
        )


        stages[1] = _build_stage(
            "extract",
            "Repository Extraction",
            "completed",
            "Repository extracted successfully.",
        )


        # ====================================================
        # SEMGREP
        # ====================================================

        stages[2] = _build_stage(
            "semgrep",
            "Security Detection",
            "running",
            "Semgrep is scanning the repository for security issues.",
        )


        findings = run_semgrep_scan(
            extract_dir
        )


        if not isinstance(
            findings,
            list,
        ):
            findings = []


        safe_findings: list[
            dict[str, Any]
        ] = []


        for finding in findings:

            if not isinstance(
                finding,
                dict,
            ):
                continue


            current_finding = _safe_finding_copy(
                finding
            )


            path = current_finding.get(
                "path",
                "",
            )


            line = _get_line_from_finding(
                current_finding
            )


            source_code = ""


            if path and line:

                try:

                    source_code = get_code_context(
                        extract_dir,
                        str(path),
                        line,
                    )

                except Exception as exc:

                    print(
                        "Source context warning:",
                        exc,
                    )


            current_finding[
                "source_code"
            ] = source_code


            safe_findings.append(
                current_finding
            )


        findings = safe_findings


        stages[2] = _build_stage(
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

        stages[3] = _build_stage(
            "risk",
            "Risk Assessment",
            "running",
            "Calculating vulnerability severity and risk.",
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


        stages[3] = _build_stage(
            "risk",
            "Risk Assessment",
            "completed",
            "Risk assessment completed.",
        )


        # ====================================================
        # GROQ AI ANALYSIS
        # ====================================================

        stages[4] = _build_stage(
            "ai",
            "AI Security Analysis",
            "running",
            "Groq AI is analyzing the detected vulnerabilities.",
        )


        ai_analysis = ""


        try:

            ai_analysis = analyze_security_findings(
                findings=findings,
                role=normalized_role,
            )

        except Exception as exc:

            raise HTTPException(
                status_code=500,
                detail=(
                    "AI security analysis failed: "
                    f"{exc}"
                ),
            ) from exc


        if not ai_analysis:

            ai_analysis = (
                "No AI analysis was generated."
            )


        stages[4] = _build_stage(
            "ai",
            "AI Security Analysis",
            "completed",
            "Groq AI security analysis completed.",
        )


        # ====================================================
        # AI AUTO-FIX
        # ====================================================

        stages[5] = _build_stage(
            "fix",
            "AI Auto-Fix",
            "running",
            "Generating corrected copies for detected vulnerabilities.",
        )


        fixes: list[dict[str, Any]] = []


        if not findings:

            stages[5] = _build_stage(
                "fix",
                "AI Auto-Fix",
                "skipped",
                "No vulnerabilities require an AI-generated fix.",
            )

        else:

            for index, finding in enumerate(
                findings
            ):

                path = finding.get(
                    "path"
                )


                source_code = finding.get(
                    "source_code",
                    "",
                )


                fix_result: dict[str, Any] = {

                    "success": False,

                    "finding_index": index,

                    "original_path": path,

                    "filename": (
                        Path(str(path)).name
                        if path
                        else None
                    ),

                    "fixed_code": None,

                    "error": None,
                }


                if not source_code:

                    fix_result[
                        "error"
                    ] = (
                        "Source context unavailable "
                        "for this finding."
                    )

                    fixes.append(
                        fix_result
                    )

                    continue


                try:

                    fixed_code = generate_fix(
                        vulnerability=finding,
                        source_code=source_code,
                    )


                    if not isinstance(
                        fixed_code,
                        str,
                    ):

                        raise ValueError(
                            "AI Auto-Fix returned an invalid response."
                        )


                    fixed_code = fixed_code.strip()


                    if not fixed_code:

                        raise ValueError(
                            "AI Auto-Fix returned empty corrected code."
                        )


                    fix_result[
                        "success"
                    ] = True


                    fix_result[
                        "fixed_code"
                    ] = fixed_code


                except Exception as exc:

                    fix_result[
                        "error"
                    ] = str(exc)


                fixes.append(
                    fix_result
                )


            successful_fixes = sum(
                1
                for fix in fixes
                if fix.get("success")
            )


            failed_fixes = (
                len(fixes)
                - successful_fixes
            )


            stages[5] = _build_stage(
                "fix",
                "AI Auto-Fix",
                "completed",
                (
                    f"{successful_fixes} fix(es) generated "
                    f"and {failed_fixes} fix(es) failed."
                ),
            )


        # ====================================================
        # VALIDATION PREPARATION
        # ====================================================

        stages[6] = _build_stage(
            "validation",
            "Validation Preparation",
            "running",
            "Preparing corrected repository output.",
        )


        validation_status = (
            "Validation preparation completed. "
            "No second security scan was performed."
        )


        stages[6] = _build_stage(
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

            "ai_analysis": ai_analysis,

            "fixes": fixes,

            "validation_status": validation_status,

            "pipeline_status": "completed",

            "stages": stages,

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
# LEGACY / INDIVIDUAL SCAN ENDPOINT
# ============================================================

@app.post("/scan/upload")
async def upload_and_scan(
    file: UploadFile = File(...),
):
    """
    Backward-compatible repository scanning endpoint.

    Phase 4 frontend should use /scan/start instead.
    """

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="Repository ZIP file is required.",
        )


    filename = Path(
        file.filename
    ).name


    if not filename.lower().endswith(
        ".zip"
    ):

        raise HTTPException(
            status_code=400,
            detail="Only ZIP repository files are supported.",
        )


    extract_dir = None


    try:

        contents = await file.read()


        if not contents:

            raise HTTPException(
                status_code=400,
                detail="Uploaded ZIP file is empty.",
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


        safe_findings = []


        for finding in findings:

            if not isinstance(
                finding,
                dict,
            ):
                continue


            current_finding = _safe_finding_copy(
                finding
            )


            path = current_finding.get(
                "path",
                "",
            )


            line = _get_line_from_finding(
                current_finding
            )


            source_code = ""


            if path and line:

                try:

                    source_code = get_code_context(
                        extract_dir,
                        str(path),
                        line,
                    )

                except Exception:

                    source_code = ""


            current_finding[
                "source_code"
            ] = source_code


            safe_findings.append(
                current_finding
            )


        findings = safe_findings


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
# LEGACY AI ANALYSIS ENDPOINT
# ============================================================

@app.post("/scan/analyze")
async def analyze_scan(
    payload: dict,
):
    """
    Backward-compatible AI analysis endpoint.

    Phase 4 frontend should use /scan/start instead.
    """

    findings = payload.get(
        "findings",
        [],
    )


    role = payload.get(
        "role",
        "developer",
    )


    try:

        normalized_role = _normalize_role(
            role
        )


        analysis = analyze_security_findings(
            findings=findings,
            role=normalized_role,
        )


        return {
            "success": True,
            "analysis": analysis,
        }


    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "AI analysis failed: "
                f"{exc}"
            ),
        ) from exc


# ============================================================
# PHASE 4 INFORMATION
# ============================================================

@app.get("/phase4")
async def phase4_info():

    return {

        "success": True,

        "phase": "Phase 4",

        "architecture": (
            "Autonomous Security Pipeline"
        ),

        "features": [

            "Repository Upload",

            "Safe ZIP Extraction",

            "Semgrep Detection",

            "Risk Assessment",

            "Groq AI Analysis",

            "AI Auto-Fix",

            "Validation Preparation",

            "Role-Based Reporting",
        ],

        "second_scan_after_fix": False,
    }