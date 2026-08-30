import io
import json
from pathlib import Path

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException,
    Form,
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from pydantic import BaseModel, EmailStr


# ============================================================
# EMAIL AGENT
# ============================================================

from app.agents.email_agent import (
    generate_security_report_html,
)

from app.services.email_service import (
    send_security_report,
)


# ============================================================
# AUTO-FIX AGENT
# ============================================================

from app.agents.auto_fix_agent import (
    generate_fix,
)

from app.services.code_context import (
    get_code_context,
)


# ============================================================
# CONFIGURATION
# ============================================================

from app.config import settings


# ============================================================
# DATABASE
# ============================================================

from app.database import (
    engine,
    Base,
)

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

from app.schemas import (
    AIAnalyzeRequest,
)

from app.ai_service import (
    analyze_with_groq,
)


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
    "http://localhost:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https://sentinelforge(?:-[a-zA-Z0-9]+)*\.vercel\.app$",
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

#Base.metadata.create_all(
  #  bind=engine)


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
# PHASE 1 + PHASE 2 + PHASE 3
# UPLOAD + SECURITY SCAN
# ============================================================

@app.post("/scan/upload")
async def upload_and_scan(
    file: UploadFile = File(...),
):

    """
    Upload ZIP repository.

    Phase 1:
        Semgrep security scan

    Phase 2:
        Risk assessment

    Phase 3:
        Attach source code context

    IMPORTANT:
        The uploaded repository is never modified.
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

                file_path = finding.get(
                    "path"
                )

                line_number = (
                    finding
                    .get("start", {})
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

                finding[
                    "source_context_error"
                ] = str(e)

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
    request: AIAnalyzeRequest,
):

    """
    Analyze security findings using Groq.
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
    # CALL GROQ
    # ========================================================

    try:

        analysis = await analyze_with_groq(
            request.findings
        )

        return {

            "success": True,

            "analysis": analysis,

        }

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
    Generate a secure fixed version of a vulnerable source file.

    IMPORTANT:

    - The original repository is NEVER modified.
    - Groq-powered Auto-Fix Agent generates the corrected code.
    - The backend creates a NEW file in memory.
    - The corrected file is returned for download.
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
    # CALL GROQ AUTO-FIX AGENT
    # ========================================================

    try:

        fix_response = generate_fix(
            vulnerability_data,
            source_code,
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                "Auto-Fix Agent failed: "
                f"{str(e)}"
            ),
        )

    # ========================================================
    # VALIDATE AI RESPONSE
    # ========================================================

    if not fix_response:

        raise HTTPException(
            status_code=500,
            detail=(
                "Auto-Fix Agent returned "
                "an empty response."
            ),
        )

    fixed_code = str(
        fix_response
    ).strip()

    # ========================================================
    # SUPPORT BOTH RESPONSE FORMATS
    # ========================================================

    if "FIXED_CODE:" in fixed_code:

        fixed_code = fixed_code.split(
            "FIXED_CODE:",
            1
        )[1].strip()

        if "EXPLANATION:" in fixed_code:

            fixed_code = fixed_code.split(
                "EXPLANATION:",
                1
            )[0].strip()

    # ========================================================
    # REMOVE MARKDOWN CODE FENCES
    # ========================================================

    if fixed_code.startswith("```"):

        lines = fixed_code.splitlines()

        # Remove first fence

        if lines and lines[0].strip().startswith("```"):

            lines = lines[1:]

        # Remove last fence

        if lines and lines[-1].strip() == "```":

            lines = lines[:-1]

        fixed_code = "\n".join(
            lines
        ).strip()

    # ========================================================
    # CHECK IF AI FAILED
    # ========================================================

    invalid_values = [

        "",

        "NOT_AVAILABLE",

        "NOT AVAILABLE",

        "UNABLE_TO_FIX",

        "UNABLE TO FIX",

    ]

    if fixed_code.strip().upper() in invalid_values:

        raise HTTPException(
            status_code=422,
            detail=(
                "Auto-Fix Agent could not "
                "safely generate a fixed file."
            ),
        )

    # ========================================================
    # GET ORIGINAL FILE PATH
    # ========================================================

    original_path = vulnerability_data.get(
        "path",
        "fixed_code.txt",
    )

    original_path = str(
        original_path
    )

    # ========================================================
    # CREATE SAFE OUTPUT FILENAME
    # ========================================================

    original_name = Path(
        original_path
    ).name

    original_stem = Path(
        original_name
    ).stem

    original_suffix = Path(
        original_name
    ).suffix

    if not original_suffix:

        original_suffix = ".txt"

    fixed_filename = (
        f"{original_stem}_fixed"
        f"{original_suffix}"
    )

    # ========================================================
    # CREATE FILE IN MEMORY
    # ========================================================

    file_bytes = fixed_code.encode(
        "utf-8"
    )

    file_stream = io.BytesIO(
        file_bytes
    )

    file_stream.seek(0)

    # ========================================================
    # RETURN FIXED FILE
    # ========================================================

    return StreamingResponse(

        file_stream,

        media_type="application/octet-stream",

        headers={

            "Content-Disposition": (
                "attachment; "
                f'filename="{fixed_filename}"'
            ),

            "X-Auto-Fix": "true",

            "X-Original-File": original_name,

            "X-Repository-Modified": "false",

        },

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

    request: EmailReportRequest,

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
            detail=(
                "RESEND_API_KEY is not configured."
            ),
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
        # ====================================================

        html_report = (
            generate_security_report_html(
                request.filename,
                request.findings,
                request.risk_assessments,
                request.overall_risk,
            )
        )

        # ====================================================
        # EMAIL SUBJECT
        # ====================================================

        subject = (
            "SentinelForge AI Security Report - "
            f"{request.filename}"
        )

        # ====================================================
        # SEND USING RESEND
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

            "message": (
                "Security report sent successfully."
            ),

            "email": str(
                request.email
            ),

            "filename": request.filename,

            "email_id": (
                result.get("id")
                if isinstance(
                    result,
                    dict,
                )
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