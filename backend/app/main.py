from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx

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

# ============================================================
# PHASE 2 - RISK ENGINE
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
# CORS
# ============================================================

# Read CORS origins from environment/config
cors_origins = [
    origin.strip()
    for origin in settings.cors_origins.split(",")
    if origin.strip()
]

# Default frontend origins
default_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://sentinelforge-ai.vercel.app",
]

# Combine configured + default origins
# and remove duplicates
allowed_origins = list(
    dict.fromkeys(
        cors_origins + default_origins
    )
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def read_root():
    return {
        "message": "SentinelForge AI backend is running",
        "environment": settings.environment,
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "sentinelforge-ai-backend",
        "environment": settings.environment,
    }


# ============================================================
# UPLOAD + SECURITY SCAN
# ============================================================

@app.post("/scan/upload")
async def upload_and_scan(file: UploadFile = File(...)):
    """
    Upload a ZIP file, scan the source code using Semgrep,
    and perform Phase 2 risk assessment.
    """

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

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
                detail=f"Unable to extract ZIP file: {str(e)}",
            )


        # ====================================================
        # PHASE 1 - SEMGREP SECURITY SCAN
        # ====================================================

        try:

            findings = run_semgrep_scan(
                extract_dir
            )

        except Exception as e:

            raise HTTPException(
                status_code=500,
                detail=f"Security scan failed: {str(e)}",
            )


        # ====================================================
        # PHASE 2 - RISK ASSESSMENT
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
                detail=f"Risk assessment failed: {str(e)}",
            )


        # ====================================================
        # RETURN SCAN + RISK RESULTS
        # ====================================================

        return {

            # -----------------------------------------------
            # Basic response information
            # -----------------------------------------------

            "success": True,

            "filename": filename,


            # -----------------------------------------------
            # PHASE 1 - Security Detection
            # -----------------------------------------------

            "findings_count": len(findings),

            "findings": findings,


            # -----------------------------------------------
            # PHASE 2 - Risk Assessment
            # -----------------------------------------------

            "risk_assessments": risk_assessments,

            "overall_risk": overall_risk,

        }


    finally:

        # ====================================================
        # CLEAN TEMPORARY FILES
        # ====================================================

        if extract_dir:

            try:

                cleanup_temp(
                    extract_dir
                )

            except Exception:

                # Cleanup failure should never hide
                # the original scan result/error.
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

    # --------------------------------------------------------
    # Validate findings
    # --------------------------------------------------------

    if not request.findings:

        raise HTTPException(
            status_code=400,
            detail="No findings to analyze.",
        )


    # --------------------------------------------------------
    # Validate API key
    # --------------------------------------------------------

    if not request.api_key:

        raise HTTPException(
            status_code=400,
            detail="AI API key is required for AI analysis.",
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


    # --------------------------------------------------------
    # AI PROVIDER HTTP ERROR
    # --------------------------------------------------------

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
            detail=f"AI provider error: {provider_message}",
        )


    # --------------------------------------------------------
    # AI PROVIDER CONNECTION ERROR
    # --------------------------------------------------------

    except httpx.RequestError:

        raise HTTPException(
            status_code=503,
            detail="Unable to connect to the AI provider.",
        )


    # --------------------------------------------------------
    # UNEXPECTED ERROR
    # --------------------------------------------------------

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"AI analysis failed: {str(e)}",
        )