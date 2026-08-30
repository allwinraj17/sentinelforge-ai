from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json
from pydantic import BaseModel, EmailStr

# ============================================================
# EMAIL AGENT
# ============================================================

from app.agents.email_agent import generate_security_report_html
from app.services.email_service import send_security_report

# ============================================================
# AUTO-FIX AGENT
# ============================================================

from app.agents.auto_fix_agent import generate_fix
from app.services.code_context import get_code_context

# ============================================================
# CONFIGURATION
# ============================================================

from app.config import settings
from app.database import engine, Base
from app import models

# ============================================================
# SCANNER
# ============================================================

from app.scanner import (
    extract_zip_to_temp,
    run_semgrep_scan,
    cleanup_temp,
)

# ============================================================
# AI ANALYSIS
# ============================================================

from app.schemas import AIAnalyzeRequest
from app.ai_service import analyze_with_gemini

# ============================================================
# RISK ENGINE
# ============================================================

from app.risk_engine import (
    assess_findings,
    calculate_overall_risk,
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SentinelForge AI",
    description="Multi-Agent Software Code Security Analysis Platform",
    version="1.0.0",
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

allowed_origins = [
    "https://sentinelforge-ai.vercel.app",
    "https://sentinelforge-ai-aaa-ac6c.vercel.app",
    "https://sentinelforge-l7z3qg4an-aaa-ac6c.vercel.app",
    "https://sentinelforge-ai-git-phase-3-aaa-ac6c.vercel.app",

    # Local development
    "http://localhost:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("============================================================")
print("SentinelForge AI - CORS Configuration")
print("============================================================")

for origin in allowed_origins:
    print(f"Allowed Origin: {origin}")

print("============================================================")


# ============================================================
# DATABASE
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def read_root():

    return {
        "message": "SentinelForge AI backend is running",
        "environment": settings.environment,
        "cors": "enabled",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health_check():

    return {
        "status": "ok",
        "service": "sentinelforge-ai-backend",
        "environment": settings.environment,
    }


# ============================================================
# PHASE 1 + PHASE 2 + PHASE 3 PREPARATION
# UPLOAD + SECURITY SCAN
# ============================================================

@app.post("/scan/upload")
async def upload_and_scan(
    file: UploadFile = File(...)
):
    """
    Upload ZIP repository.

    Phase 1:
        Semgrep security scan

    Phase 2:
        Risk assessment

    Phase 3:
        Attach source code context
    """

    # ========================================================
    # VALIDATE FILE
    # ========================================================

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename was provided.",
        )

    filename = file.filename.strip()

    if not filename.lower().endswith(".zip"):

        raise HTTPException(
            status_code=400,
            detail="Only .zip files are supported.",
        )

    extract_dir = None

    try:

        # ====================================================
        # READ UPLOADED FILE
        # ====================================================

        contents = await file.read()

        if not contents:

            raise HTTPException(
                status_code=400,
                detail="The uploaded ZIP file is empty.",
            )

        # ====================================================
        # EXTRACT ZIP
        # ====================================================

        try:

            extract_dir = extract_zip_to_temp(
                contents
            )

        except ValueError as e:

            raise HTTPException(
                status_code=400,
                detail=str(e),
            )

        except Exception as e:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Unable to extract ZIP file: "
                    f"{str(e)}"
                ),
            )

        # ====================================================
        # PHASE 1
        # SEMGREP SECURITY SCAN
        # ====================================================

        try:

            findings = run_semgrep_scan(
                extract_dir
            )

        except Exception as e:

            raise HTTPException(
                status_code=500,
                detail=(
                    "Security scan failed: "
                    f"{str(e)}"
                ),
            )

        # ====================================================
        # PHASE 2
        # RISK ASSESSMENT
        # ====================================================

        try:

            risk_assessments = assess_findings(
                findings
            )

            overall_risk = calculate_overall_risk(
                risk_assessments
            )

        except Exception as e:

            raise HTTPException(
                status_code=500,
                detail=(
                    "Risk assessment failed: "
                    f"{str(e)}"
                ),
            )

        # ====================================================
        # PHASE 3
        # ATTACH SOURCE CODE CONTEXT
        # ====================================================

        for finding in findings:

            try:

                file_path = finding.get("path")

                line_number = (
                    finding.get("start", {})
                    .get("line")
                )

                if file_path and line_number:

                    finding["source_code"] = (
                        get_code_context(
                            extract_dir,
                            file_path,
                            line_number,
                        )
                    )

                else:

                    finding["source_code"] = ""

            except Exception as e:

                finding["source_code"] = ""

                finding["source_context_error"] = (
                    str(e)
                )

        # ====================================================
        # RETURN RESULTS
        # ====================================================

        return {
            "success": True,
            "filename": filename,
            "findings_count": len(findings),
            "findings": findings,
            "risk_assessments": risk_assessments,
            "overall_risk": overall_risk,
        }

    finally:

        # ====================================================
        # CLEAN TEMP FILES
        # ====================================================

        if extract_dir:

            try:

                cleanup_temp(
                    extract_dir
                )

            except Exception:

                pass


# ============================================================
# AI ANALYSIS
# ============================================================

@app.post("/scan/analyze")
async def analyze_findings(
    request: AIAnalyzeRequest
):
    """
    Analyze security findings using AI.
    """

    if not request.findings:

        raise HTTPException(
            status_code=400,
            detail="No findings to analyze.",
        )

    if not request.api_key:

        raise HTTPException(
            status_code=400,
            detail=(
                "AI API key is required "
                "for AI analysis."
            ),
        )

    try:

        analysis = await analyze_with_gemini(
            request.api_key,
            request.findings,
        )

        return {
            "success": True,
            "analysis": analysis,
        }

    except httpx.HTTPStatusError as e:

        provider_message = (
            "AI provider request failed."
        )

        try:

            provider_message = e.response.text

        except Exception:

            pass

        raise HTTPException(
            status_code=400,
            detail=(
                "AI provider error: "
                f"{provider_message}"
            ),
        )

    except httpx.RequestError:

        raise HTTPException(
            status_code=503,
            detail=(
                "Unable to connect to "
                "the AI provider."
            ),
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                "AI analysis failed: "
                f"{str(e)}"
            ),
        )


# ============================================================
# PHASE 3
# AUTO-FIX AGENT
# ============================================================

@app.post("/scan/auto-fix")
async def generate_auto_fix(
    vulnerability: str = Form(...),
    source_code: str = Form(...),
):
    """
    Generate a secure code-fix suggestion.

    The repository is NOT modified.
    """

    # ========================================================
    # PARSE VULNERABILITY DATA
    # ========================================================

    try:

        vulnerability_data = json.loads(
            vulnerability
        )

    except json.JSONDecodeError:

        raise HTTPException(
            status_code=400,
            detail="Invalid vulnerability data.",
        )

    # ========================================================
    # VALIDATE SOURCE CODE
    # ========================================================

    if not source_code.strip():

        raise HTTPException(
            status_code=400,
            detail="Source code is required.",
        )

    # ========================================================
    # CALL AUTO-FIX AGENT
    # ========================================================

    try:

        fix = generate_fix(
            vulnerability_data,
            source_code,
        )

        return {
            "success": True,
            "fix": fix,
            "repository_modified": False,
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                "Auto-Fix Agent failed: "
                f"{str(e)}"
            ),
        )


# ============================================================
# EMAIL REPORT REQUEST
# ============================================================

class EmailReportRequest(BaseModel):

    email: EmailStr

    filename: str

    findings: list

    risk_assessments: list

    overall_risk: dict


# ============================================================
# PHASE 3
# EMAIL SECURITY REPORT AGENT
# ============================================================

@app.post("/scan/email-report")
async def email_security_report(
    request: EmailReportRequest
):
    """
    Generate a professional security report
    and send it to the user's email using Resend.
    """

    # ========================================================
    # CHECK RESEND API KEY
    # ========================================================

    if not settings.resend_api_key:

        raise HTTPException(
            status_code=500,
            detail="RESEND_API_KEY is not configured.",
        )

    # ========================================================
    # CHECK FINDINGS
    # ========================================================

    if request.findings is None:

        raise HTTPException(
            status_code=400,
            detail="Findings are required.",
        )

    try:

        # ====================================================
        # EMAIL AGENT
        # GENERATE HTML
        # ====================================================

        html_report = generate_security_report_html(
            request.filename,
            request.findings,
            request.risk_assessments,
            request.overall_risk,
        )

        # ====================================================
        # EMAIL SUBJECT
        # ====================================================

        subject = (
            "SentinelForge AI Security Report - "
            f"{request.filename}"
        )

        # ====================================================
        # RESEND
        # ====================================================

        result = send_security_report(
            str(request.email),
            subject,
            html_report,
        )

        # ====================================================
        # SUCCESS
        # ====================================================

        return {
            "success": True,
            "message": "Security report sent successfully.",
            "email": str(request.email),
            "filename": request.filename,
            "email_id": (
                result.get("id")
                if isinstance(result, dict)
                else None
            ),
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                "Email Agent failed: "
                f"{str(e)}"
            ),
        )

