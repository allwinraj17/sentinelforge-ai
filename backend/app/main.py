from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json

from app.agents.auto_fix_agent import generate_fix
from app.services.code_context import get_code_context

from app.config import settings
from app.database import engine, Base
from app import models

from app.scanner import (
    extract_zip_to_temp,
    run_semgrep_scan,
    cleanup_temp,
)

from app.schemas import AIAnalyzeRequest
from app.ai_service import analyze_with_gemini

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

# ============================================================
# CORS CONFIGURATION
# ============================================================

allowed_origins = [
    "https://sentinelforge-ai.vercel.app",
    "https://sentinelforge-ai-aaa-ac6c.vercel.app",
    "https://sentinelforge-l7z3qg4an-aaa-ac6c.vercel.app",
    "https://sentinelforge-ai-git-phase-3-aaa-ac6c.vercel.app",

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
    Upload a ZIP file.

    Phase 1:
        Semgrep security scan

    Phase 2:
        Risk assessment

    Phase 3 preparation:
        Attach source code context to each finding

    The actual Auto-Fix Agent is called separately
    through /scan/auto-fix.
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
        # PHASE 3 PREPARATION
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

                # Never hide original result/error
                pass


# ============================================================
# AI ANALYSIS
# ============================================================

@app.post("/scan/analyze")
async def analyze_findings(
    request: AIAnalyzeRequest
):
    """
    Analyze security findings using the configured
    AI provider.
    """

    # ========================================================
    # VALIDATE FINDINGS
    # ========================================================

    if not request.findings:

        raise HTTPException(
            status_code=400,
            detail="No findings to analyze.",
        )

    # ========================================================
    # VALIDATE API KEY
    # ========================================================

    if not request.api_key:

        raise HTTPException(
            status_code=400,
            detail=(
                "AI API key is required "
                "for AI analysis."
            ),
        )

    try:

        # ====================================================
        # CALL AI SERVICE
        # ====================================================

        analysis = await analyze_with_gemini(
            request.api_key,
            request.findings,
        )

        return {
            "success": True,
            "analysis": analysis,
        }

    # ========================================================
    # AI PROVIDER HTTP ERROR
    # ========================================================

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

    # ========================================================
    # AI PROVIDER CONNECTION ERROR
    # ========================================================

    except httpx.RequestError:

        raise HTTPException(
            status_code=503,
            detail=(
                "Unable to connect to "
                "the AI provider."
            ),
        )

    # ========================================================
    # UNEXPECTED ERROR
    # ========================================================

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
