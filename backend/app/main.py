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
# DATABASE
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="SentinelForge AI",
    description="Multi-Agent Software Repository Security Analysis Platform",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

cors_origins = [
    origin.strip()
    for origin in settings.cors_origins.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    Upload a ZIP repository and run a security scan.
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
        # ----------------------------------------------------
        # Read uploaded file
        # ----------------------------------------------------

        contents = await file.read()

        if not contents:
            raise HTTPException(
                status_code=400,
                detail="The uploaded ZIP file is empty.",
            )

        # ----------------------------------------------------
        # Extract ZIP
        # ----------------------------------------------------

        try:
            extract_dir = extract_zip_to_temp(contents)
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

        # ----------------------------------------------------
        # Run Semgrep
        # ----------------------------------------------------

        try:
            findings = run_semgrep_scan(extract_dir)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Security scan failed: {str(e)}",
            )

        # ----------------------------------------------------
        # Return results
        # ----------------------------------------------------

        return {
            "success": True,
            "filename": filename,
            "findings_count": len(findings),
            "findings": findings,
        }

    finally:
        # ----------------------------------------------------
        # Always clean temporary files
        # ----------------------------------------------------

        if extract_dir:
            try:
                cleanup_temp(extract_dir)
            except Exception:
                # Cleanup failure should not hide the original
                # scan result/error.
                pass


# ============================================================
# AI ANALYSIS
# ============================================================

@app.post("/scan/analyze")
async def analyze_findings(request: AIAnalyzeRequest):
    """
    Analyze security findings using the configured AI provider.
    """

    if not request.findings:
        raise HTTPException(
            status_code=400,
            detail="No findings to analyze.",
        )

    if not request.api_key:
        raise HTTPException(
            status_code=400,
            detail="AI API key is required for AI analysis.",
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
        provider_message = "AI provider request failed."

        try:
            provider_message = e.response.text
        except Exception:
            pass

        raise HTTPException(
            status_code=400,
            detail=f"AI provider error: {provider_message}",
        )

    except httpx.RequestError:
        raise HTTPException(
            status_code=503,
            detail="Unable to connect to the AI provider.",
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"AI analysis failed: {str(e)}",
        )