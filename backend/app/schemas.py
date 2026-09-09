from typing import Any

from pydantic import BaseModel, EmailStr, Field


# ============================================================
# PHASE 4 - AUTONOMOUS SCAN REQUEST
# ============================================================

class AutonomousScanRequest(BaseModel):
    """
    Request data for the Phase 4 autonomous security workflow.

    The repository ZIP itself is received separately through
    FastAPI UploadFile. This model contains only the user-supplied
    metadata required by the autonomous agent.
    """

    role: str = Field(
        ...,
        description="User role: student or developer.",
    )

    email: EmailStr = Field(
        ...,
        description="Email address for the security report.",
    )


# ============================================================
# PHASE 4 - AI ANALYSIS RESULT
# ============================================================

class AIAnalysisResult(BaseModel):
    """
    Structured representation of an AI analysis result.
    """

    success: bool = True

    analysis: str = ""


# ============================================================
# PHASE 4 - AUTO-FIX RESULT
# ============================================================

class AutoFixResult(BaseModel):
    """
    Result returned by the Auto-Fix Agent for one finding.
    """

    success: bool = True

    finding_index: int

    original_path: str | None = None

    filename: str | None = None

    fixed_code: str | None = None

    error: str | None = None


# ============================================================
# PHASE 4 - PIPELINE STAGE RESULT
# ============================================================

class PipelineStageResult(BaseModel):
    """
    Represents the state of one autonomous pipeline stage.
    """

    id: str

    title: str

    status: str

    message: str = ""


# ============================================================
# PHASE 4 - AUTONOMOUS SCAN RESPONSE
# ============================================================

class AutonomousScanResponse(BaseModel):
    """
    Complete response returned by the Phase 4 autonomous
    backend pipeline.
    """

    success: bool

    filename: str

    role: str

    email: str

    findings_count: int

    findings: list[dict[str, Any]]

    risk_assessments: list[dict[str, Any]]

    overall_risk: dict[str, Any]

    ai_analysis: str = ""

    fixes: list[AutoFixResult] = []

    validation_status: str = (
        "Validation preparation completed. "
        "No second security scan was performed."
    )

    pipeline_status: str = "completed"

    stages: list[PipelineStageResult] = []