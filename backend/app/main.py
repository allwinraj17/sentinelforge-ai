from __future__ import annotations

import asyncio
import io
import json
import uuid
import zipfile
from pathlib import Path
from typing import Any
from contextvars import ContextVar

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.agents.auto_fix_agent import generate_fix
from app.agents.validation_agent import run_validation_agent

from app.agents.repository_understanding_agent import (
    run_repository_understanding,
)

from app.agents.secret_detection_agent import (
    run_secret_detection,
)

from app.agents.compliance_agent import (
    run_compliance_agent,
)

from app.agents.ml_triage_agent import run_ml_triage
from app.agents.ml_classification_agent import run_ml_classification
from app.agents.ml_severity_agent import run_ml_severity
from app.agents.ml_priority_agent import run_ml_priority
from app.agents.ml_code_context_agent import run_ml_code_context
from app.agents.ml_similarity_agent import run_ml_similarity
from app.agents.ml_fix_recommendation_agent import run_ml_fix_recommendation

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

APP_VERSION = "7.0.0"

app = FastAPI(
    title=(
        "A Multi-Agent System for Automated "
        "Software Repository Security Analysis"
    ),
    description=(
        "Automated software repository security analysis "
        "using specialized security agents, Semgrep, "
        "risk assessment, AI-assisted remediation, "
        "compliance mapping and validation."
    ),
    version=APP_VERSION,
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
            default_origins
            + configured_origins
        )
    )
else:
    allowed_origins = default_origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=(
        r"https://sentinelforge-.*\.vercel\.app"
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
# REAL-TIME SCAN JOB STATE
# ============================================================

SCAN_JOBS: dict[str, dict[str, Any]] = {}

CURRENT_SCAN_JOB = ContextVar(
    "CURRENT_SCAN_JOB",
    default=None,
)


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
    Build a frontend-friendly stage object and, when a scan job
    is active, publish the same stage state to that job.
    """

    stage = {
        "id": stage_id,
        "title": title,
        "status": status,
        "message": message,
    }

    job_id = CURRENT_SCAN_JOB.get()

    if job_id:
        job = SCAN_JOBS.get(job_id)

        if job is not None:
            stages = job.get("stages", [])

            for index, existing_stage in enumerate(stages):
                if existing_stage.get("id") == stage_id:
                    stages[index] = stage
                    break

            job["stages"] = stages

    return stage


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
    Convert Semgrep absolute path into
    repository-relative path.
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
    Group security findings by repository file.

    Multiple findings in the same source file are
    combined into one AI Auto-Fix request.

    This prevents unnecessary repeated Groq calls.
    """

    groups: dict[
        str,
        list[dict[str, Any]]
    ] = {}

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


def build_ml_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert a Semgrep finding into the common flat structure
    expected by the ML agents.

    The original Semgrep finding is never replaced; this is only
    a separate ML input representation.
    """

    extra = finding.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}

    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    message = (
        extra.get("message")
        or finding.get("message")
        or finding.get("check_id")
        or "Security finding"
    )

    severity = (
        extra.get("severity")
        or metadata.get("severity")
        or finding.get("severity")
        or "INFO"
    )

    cwe = metadata.get("cwe", finding.get("cwe", ""))
    if isinstance(cwe, list):
        cwe = ", ".join(str(item) for item in cwe)

    source_type = (
        metadata.get("source")
        or finding.get("source_type")
        or "semgrep"
    )

    vulnerability_type = (
        metadata.get("vulnerability_class")
        or finding.get("vulnerability_type")
        or "Other"
    )

    return {
        "message": str(message),
        "finding_text": str(message),
        "vulnerability_type": str(vulnerability_type),
        "cwe": str(cwe),
        "source_type": str(source_type),
        "path": str(finding.get("path", "")),
        "severity": str(severity),
        "user_input": int(finding.get("user_input", 0) or 0),
        "dangerous_api": int(finding.get("dangerous_api", 0) or 0),
        "production_context": int(finding.get("production_context", 0) or 0),
        "exposure": int(finding.get("exposure", 0) or 0),
        "exploitability": int(finding.get("exploitability", 0) or 0),
    }


def build_ml_error(
    agent_name: str,
    model_name: str,
    total: int,
    error: str,
) -> dict[str, Any]:
    """Build a consistent non-fatal ML agent error response."""

    return {
        "agent": agent_name,
        "success": False,
        "model": model_name,
        "total_findings": total,
        "results": [],
        "error": error,
    }


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

        "version": APP_VERSION,

        "phase": "Phase 7 - ML Security Intelligence",

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

        "service": (
            "sentinelforge-ai-backend"
        ),

        "environment": getattr(
            settings,
            "environment",
            "development",
        ),

        "version": APP_VERSION,

        "phase": "Phase 7 - ML Security Intelligence",
    }


# ============================================================
# REAL-TIME SCAN JOB API
# ============================================================

@app.post("/scan/start-job")
async def start_scan_job(
    role: str = Form(...),
    email: str = Form(...),
    file: UploadFile = File(...),
):
    """
    Start the existing security pipeline as a background job.

    The client receives a job_id immediately and polls the status
    endpoint. Stage status is published by the actual backend
    pipeline, so the progress UI is not based on fixed timers.
    """

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Repository ZIP file is required.",
        )

    original_filename = Path(file.filename).name

    if not original_filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Only ZIP repository files are supported.",
        )

    contents = await file.read()

    if not contents:
        raise HTTPException(
            status_code=400,
            detail="Uploaded ZIP file is empty.",
        )

    if len(contents) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Repository ZIP exceeds the 50 MB upload limit.",
        )

    job_id = str(uuid.uuid4())

    SCAN_JOBS[job_id] = {
        "job_id": job_id,
        "status": "starting",
        "stages": [],
        "result": None,
        "error": None,
    }

    async def run_job():
        token = CURRENT_SCAN_JOB.set(job_id)

        try:
            SCAN_JOBS[job_id]["status"] = "running"

            background_file = UploadFile(
                file=io.BytesIO(contents),
                filename=original_filename,
            )

            result = await start_autonomous_scan(
                role=role,
                email=email,
                file=background_file,
            )

            SCAN_JOBS[job_id]["result"] = result
            SCAN_JOBS[job_id]["stages"] = result.get(
                "stages",
                SCAN_JOBS[job_id].get("stages", []),
            )
            SCAN_JOBS[job_id]["status"] = "completed"

        except HTTPException as exc:
            SCAN_JOBS[job_id]["status"] = "failed"
            SCAN_JOBS[job_id]["error"] = str(exc.detail)

        except Exception as exc:
            SCAN_JOBS[job_id]["status"] = "failed"
            SCAN_JOBS[job_id]["error"] = str(exc)

        finally:
            CURRENT_SCAN_JOB.reset(token)

    asyncio.create_task(run_job())

    return {
        "success": True,
        "job_id": job_id,
        "message": "Security analysis started.",
    }


@app.get("/scan/status/{job_id}")
async def get_scan_status(job_id: str):
    """Return real-time backend stage state for a scan job."""

    job = SCAN_JOBS.get(job_id)

    if job is None:
        raise HTTPException(
            status_code=404,
            detail="Scan job not found.",
        )

    return {
        "success": True,
        "job_id": job_id,
        "status": job.get("status"),
        "stages": job.get("stages", []),
        "result": job.get("result"),
        "error": job.get("error"),
    }


# ============================================================
# MASTER AUTONOMOUS SCAN - PHASE 7
# ============================================================

@app.post("/scan/start")
async def start_autonomous_scan(
    role: str = Form(...),
    email: str = Form(...),
    file: UploadFile = File(...),
):
    """
    PHASE 5 AUTONOMOUS SECURITY PIPELINE

        Repository ZIP
              ↓
        Safe Extraction
              ↓
        Repository Understanding Agent
              ↓
        Semgrep Security Detection
              ↓
        Secret Detection Agent
              ↓
        ML Security Intelligence
        ├── Vulnerability Triage
        ├── Vulnerability Classification
        ├── Severity Prediction
        ├── Priority Prediction
        ├── Code Context Analysis
        ├── Duplicate Similarity
        └── Fix Recommendation
              ↓
        Combined Security Findings
              ↓
        Risk Assessment
              ↓
        Compliance Agent
              ↓
        OWASP Top 10 Mapping
              ↓
        AI Auto-Fix
              ↓
        Validation Agent
              ↓
        Final Results

    Groq is used ONLY for AI Auto-Fix.

    Multiple findings belonging to the same source
    file are combined into one Auto-Fix request.

    Maximum UNIQUE source files sent to Groq = 3.

    No second Semgrep scan is performed.

    Original uploaded repository is not modified.
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
    # PHASE 5 PIPELINE STAGES
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
            "understanding",
            "Repository Understanding",
            "pending",
        ),

        build_stage(
            "semgrep",
            "Security Detection",
            "pending",
        ),

        build_stage(
            "secret",
            "Secret Detection",
            "pending",
        ),

        build_stage("ml_triage", "ML Vulnerability Triage", "pending"),
        build_stage("ml_classification", "ML Vulnerability Classification", "pending"),
        build_stage("ml_severity", "ML Severity Prediction", "pending"),
        build_stage("ml_priority", "ML Priority Prediction", "pending"),
        build_stage("ml_code_context", "ML Code Context Analysis", "pending"),
        build_stage("ml_similarity", "ML Duplicate Similarity", "pending"),
        build_stage("ml_fix_recommendation", "ML Fix Recommendation", "pending"),

        build_stage(
            "risk",
            "Risk Assessment",
            "pending",
        ),

        build_stage(
            "compliance",
            "Compliance Mapping",
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

    job_id = CURRENT_SCAN_JOB.get()

    if job_id:
        job = SCAN_JOBS.get(job_id)

        if job is not None:
            job["stages"] = stages
            job["status"] = "running"


    extract_dir = None


    # ========================================================
    # INITIALIZE RESULTS
    # ========================================================

    repository_understanding = {
        "agent": (
            "Repository Understanding Agent"
        ),
        "success": False,
        "total_files": 0,
        "source_files": 0,
        "languages": {},
        "dependency_files": [],
        "configuration_files": [],
        "authentication_related_files": [],
        "database_related_files": [],
        "repository_structure": [],
    }


    secret_detection = {
        "agent": (
            "Secret Detection Agent"
        ),
        "success": False,
        "findings_count": 0,
        "findings": [],
    }


    compliance_result = {
        "agent": "Compliance Agent",
        "success": False,
        "framework": "OWASP Top 10 2021",
        "findings_mapped": 0,
        "mappings": [],
        "category_counts": {},
    }


    ml_triage_result = build_ml_error(
        "ML Vulnerability Triage Agent",
        "TF-IDF + Logistic Regression",
        0,
        "Not executed yet.",
    )
    ml_classification_result = build_ml_error(
        "ML Vulnerability Classification Agent",
        "TF-IDF + Linear SVM",
        0,
        "Not executed yet.",
    )
    ml_severity_result = build_ml_error(
        "ML Severity Prediction Agent",
        "TF-IDF + One-Hot Encoding + Random Forest",
        0,
        "Not executed yet.",
    )
    ml_priority_result = build_ml_error(
        "ML Priority Prediction Agent",
        "TF-IDF + One-Hot Encoding + Random Forest",
        0,
        "Not executed yet.",
    )
    ml_code_context_result = build_ml_error(
        "ML Code Context Analysis Agent",
        "TF-IDF + Linear SVM",
        0,
        "Not executed yet.",
    )
    ml_similarity_result = {
        "agent": "ML Duplicate Vulnerability Similarity Agent",
        "success": False,
        "model": "TF-IDF + Cosine Similarity",
        "total_pairs": 0,
        "results": [],
        "error": "Not executed yet.",
    }
    ml_fix_recommendation_result = build_ml_error(
        "ML Fix Recommendation Agent",
        "TF-IDF + Logistic Regression",
        0,
        "Not executed yet.",
    )

    findings = []

    secret_findings = []

    all_security_findings = []

    risk_assessments = []

    overall_risk = {}

    fixes = []

    validation_result = {}

    successful_fixes = 0


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
        # REPOSITORY UNDERSTANDING AGENT
        # ====================================================

        stages[2] = build_stage(
            "understanding",
            "Repository Understanding",
            "running",
            (
                "Analyzing repository structure, "
                "languages and important files."
            ),
        )


        try:

            repository_understanding = (
                run_repository_understanding(
                    extract_dir
                )
            )

        except Exception as exc:

            print(
                "Repository Understanding Agent error:",
                exc,
            )

            repository_understanding = {
                "agent": (
                    "Repository Understanding Agent"
                ),
                "success": False,
                "error": str(exc),
                "total_files": 0,
                "source_files": 0,
                "languages": {},
                "dependency_files": [],
                "configuration_files": [],
                "authentication_related_files": [],
                "database_related_files": [],
                "repository_structure": [],
            }


        understanding_file_count = (
            repository_understanding.get(
                "total_files",
                0,
            )
        )


        stages[2] = build_stage(
            "understanding",
            "Repository Understanding",
            "completed",
            (
                f"{understanding_file_count} "
                "repository file(s) analyzed."
            ),
        )


        # ====================================================
        # SEMGREP SECURITY DETECTION
        # ====================================================

        stages[3] = build_stage(
            "semgrep",
            "Security Detection",
            "running",
            (
                "Semgrep is scanning the repository "
                "for security vulnerabilities."
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
        # NORMALIZE SEMGREP FINDING PATHS
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


        stages[3] = build_stage(
            "semgrep",
            "Security Detection",
            "completed",
            (
                f"{len(findings)} "
                "Semgrep security finding(s) detected."
            ),
        )


        # ====================================================
        # SECRET DETECTION AGENT
        # ====================================================

        stages[4] = build_stage(
            "secret",
            "Secret Detection",
            "running",
            (
                "Scanning repository files for "
                "potential exposed secrets."
            ),
        )


        try:

            secret_detection = (
                run_secret_detection(
                    extract_dir
                )
            )

        except Exception as exc:

            print(
                "Secret Detection Agent error:",
                exc,
            )

            secret_detection = {
                "agent": (
                    "Secret Detection Agent"
                ),
                "success": False,
                "findings_count": 0,
                "findings": [],
                "error": str(exc),
            }


        secret_findings = (
            secret_detection.get(
                "findings",
                [],
            )
        )


        if not isinstance(
            secret_findings,
            list,
        ):

            secret_findings = []


        stages[4] = build_stage(
            "secret",
            "Secret Detection",
            "completed",
            (
                f"{len(secret_findings)} "
                "potential secret finding(s) detected."
            ),
        )


        # ====================================================
        # ML SECURITY INTELLIGENCE
        # ====================================================
        # ML receives normalized Semgrep findings only.
        # Secret findings remain in the existing security workflow.

        ml_findings = [
            build_ml_finding(item)
            for item in findings
            if isinstance(item, dict)
        ]

        # ---------------- ML TRIAGE ----------------
        stages[5] = build_stage(
            "ml_triage",
            "ML Vulnerability Triage",
            "running",
            "Estimating whether detected findings are likely vulnerabilities.",
        )
        try:
            ml_triage_result = run_ml_triage(ml_findings)
            if not isinstance(ml_triage_result, dict):
                ml_triage_result = build_ml_error(
                    "ML Vulnerability Triage Agent",
                    "TF-IDF + Logistic Regression",
                    len(ml_findings),
                    "Invalid ML triage response.",
                )
        except Exception as exc:
            ml_triage_result = build_ml_error(
                "ML Vulnerability Triage Agent",
                "TF-IDF + Logistic Regression",
                len(ml_findings),
                str(exc),
            )
        stages[5] = build_stage(
            "ml_triage",
            "ML Vulnerability Triage",
            "completed" if ml_triage_result.get("success") else "attention",
            f"{len(ml_triage_result.get('results', []))} finding(s) analyzed.",
        )

        # ---------------- ML CLASSIFICATION ----------------
        stages[6] = build_stage(
            "ml_classification",
            "ML Vulnerability Classification",
            "running",
            "Predicting the vulnerability category of detected findings.",
        )
        try:
            ml_classification_result = run_ml_classification(ml_findings)
            if not isinstance(ml_classification_result, dict):
                ml_classification_result = build_ml_error(
                    "ML Vulnerability Classification Agent",
                    "TF-IDF + Linear SVM",
                    len(ml_findings),
                    "Invalid ML classification response.",
                )
        except Exception as exc:
            ml_classification_result = build_ml_error(
                "ML Vulnerability Classification Agent",
                "TF-IDF + Linear SVM",
                len(ml_findings),
                str(exc),
            )
        stages[6] = build_stage(
            "ml_classification",
            "ML Vulnerability Classification",
            "completed" if ml_classification_result.get("success") else "attention",
            f"{len(ml_classification_result.get('results', []))} finding(s) classified.",
        )

        # ---------------- ML SEVERITY ----------------
        stages[7] = build_stage(
            "ml_severity",
            "ML Severity Prediction",
            "running",
            "Predicting supporting severity labels from security context.",
        )
        try:
            ml_severity_result = run_ml_severity(ml_findings)
            if not isinstance(ml_severity_result, dict):
                ml_severity_result = build_ml_error(
                    "ML Severity Prediction Agent",
                    "TF-IDF + One-Hot Encoding + Random Forest",
                    len(ml_findings),
                    "Invalid ML severity response.",
                )
        except Exception as exc:
            ml_severity_result = build_ml_error(
                "ML Severity Prediction Agent",
                "TF-IDF + One-Hot Encoding + Random Forest",
                len(ml_findings),
                str(exc),
            )
        stages[7] = build_stage(
            "ml_severity",
            "ML Severity Prediction",
            "completed" if ml_severity_result.get("success") else "attention",
            f"{len(ml_severity_result.get('results', []))} finding(s) scored by the ML model.",
        )

        # ---------------- ML PRIORITY ----------------
        stages[8] = build_stage(
            "ml_priority",
            "ML Priority Prediction",
            "running",
            "Predicting remediation investigation priority.",
        )
        try:
            ml_priority_result = run_ml_priority(ml_findings)
            if not isinstance(ml_priority_result, dict):
                ml_priority_result = build_ml_error(
                    "ML Priority Prediction Agent",
                    "TF-IDF + One-Hot Encoding + Random Forest",
                    len(ml_findings),
                    "Invalid ML priority response.",
                )
        except Exception as exc:
            ml_priority_result = build_ml_error(
                "ML Priority Prediction Agent",
                "TF-IDF + One-Hot Encoding + Random Forest",
                len(ml_findings),
                str(exc),
            )
        stages[8] = build_stage(
            "ml_priority",
            "ML Priority Prediction",
            "completed" if ml_priority_result.get("success") else "attention",
            f"{len(ml_priority_result.get('results', []))} finding(s) prioritized.",
        )

        # ---------------- ML CODE CONTEXT ----------------
        stages[9] = build_stage(
            "ml_code_context",
            "ML Code Context Analysis",
            "running",
            "Analyzing the source context associated with detected findings.",
        )
        try:
            ml_code_context_result = run_ml_code_context(ml_findings)
            if not isinstance(ml_code_context_result, dict):
                ml_code_context_result = build_ml_error(
                    "ML Code Context Analysis Agent",
                    "TF-IDF + Linear SVM",
                    len(ml_findings),
                    "Invalid ML code context response.",
                )
        except Exception as exc:
            ml_code_context_result = build_ml_error(
                "ML Code Context Analysis Agent",
                "TF-IDF + Linear SVM",
                len(ml_findings),
                str(exc),
            )
        stages[9] = build_stage(
            "ml_code_context",
            "ML Code Context Analysis",
            "completed" if ml_code_context_result.get("success") else "attention",
            f"{len(ml_code_context_result.get('results', []))} finding(s) contextualized.",
        )

        # ---------------- ML SIMILARITY ----------------
        stages[10] = build_stage(
            "ml_similarity",
            "ML Duplicate Similarity",
            "running",
            "Comparing findings to identify related or duplicate vulnerabilities.",
        )
        try:
            similarity_pairs = []
            for first_index in range(len(ml_findings)):
                for second_index in range(first_index + 1, len(ml_findings)):
                    similarity_pairs.append({
                        "finding_1": ml_findings[first_index],
                        "finding_2": ml_findings[second_index],
                    })
            ml_similarity_result = run_ml_similarity(similarity_pairs)
            if not isinstance(ml_similarity_result, dict):
                ml_similarity_result = {
                    "agent": "ML Duplicate Vulnerability Similarity Agent",
                    "success": False,
                    "model": "TF-IDF + Cosine Similarity",
                    "total_pairs": len(similarity_pairs),
                    "results": [],
                    "error": "Invalid ML similarity response.",
                }
        except Exception as exc:
            ml_similarity_result = {
                "agent": "ML Duplicate Vulnerability Similarity Agent",
                "success": False,
                "model": "TF-IDF + Cosine Similarity",
                "total_pairs": 0,
                "results": [],
                "error": str(exc),
            }
        stages[10] = build_stage(
            "ml_similarity",
            "ML Duplicate Similarity",
            "completed" if ml_similarity_result.get("success") else "attention",
            f"{len(ml_similarity_result.get('results', []))} finding pair(s) compared.",
        )

        # ---------------- ML FIX RECOMMENDATION ----------------
        stages[11] = build_stage(
            "ml_fix_recommendation",
            "ML Fix Recommendation",
            "running",
            "Recommending security remediation strategies.",
        )
        try:
            ml_fix_recommendation_result = run_ml_fix_recommendation(ml_findings)
            if not isinstance(ml_fix_recommendation_result, dict):
                ml_fix_recommendation_result = build_ml_error(
                    "ML Fix Recommendation Agent",
                    "TF-IDF + Logistic Regression",
                    len(ml_findings),
                    "Invalid ML fix recommendation response.",
                )
        except Exception as exc:
            ml_fix_recommendation_result = build_ml_error(
                "ML Fix Recommendation Agent",
                "TF-IDF + Logistic Regression",
                len(ml_findings),
                str(exc),
            )
        stages[11] = build_stage(
            "ml_fix_recommendation",
            "ML Fix Recommendation",
            "completed" if ml_fix_recommendation_result.get("success") else "attention",
            f"{len(ml_fix_recommendation_result.get('results', []))} remediation recommendation(s) generated.",
        )

        # ====================================================
        # COMBINE SECURITY FINDINGS
        # ====================================================

        all_security_findings = (
            findings
            + secret_findings
        )


        # ====================================================
        # RISK ASSESSMENT
        # ====================================================

        stages[12] = build_stage(
            "risk",
            "Risk Assessment",
            "running",
            (
                "Calculating vulnerability severity "
                "and overall risk."
            ),
        )


        try:

            risk_assessments = (
                assess_findings(
                    all_security_findings
                )
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

            overall_risk = (
                calculate_overall_risk(
                    risk_assessments
                )
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


        stages[12] = build_stage(
            "risk",
            "Risk Assessment",
            "completed",
            (
                "Risk assessment completed."
            ),
        )


        # ====================================================
        # COMPLIANCE / OWASP AGENT
        # ====================================================

        stages[13] = build_stage(
            "compliance",
            "Compliance Mapping",
            "running",
            (
                "Mapping security findings "
                "to OWASP Top 10 2021 categories."
            ),
        )


        try:

            compliance_result = (
                run_compliance_agent(
                    all_security_findings
                )
            )

        except Exception as exc:

            print(
                "Compliance Agent error:",
                exc,
            )

            compliance_result = {
                "agent": "Compliance Agent",
                "success": False,
                "framework": (
                    "OWASP Top 10 2021"
                ),
                "findings_mapped": 0,
                "mappings": [],
                "category_counts": {},
                "error": str(exc),
            }


        mapped_count = (
            compliance_result.get(
                "findings_mapped",
                0,
            )
        )


        stages[13] = build_stage(
            "compliance",
            "Compliance Mapping",
            "completed",
            (
                f"{mapped_count} "
                "finding(s) mapped to OWASP categories."
            ),
        )


        # ====================================================
        # GROUP FINDINGS BY SOURCE FILE
        # ====================================================

        grouped_findings = (
            group_findings_by_file(
                all_security_findings
            )
        )


        # ====================================================
        # GROQ AI AUTO-FIX
        # ====================================================

        stages[14] = build_stage(
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

            stages[14] = build_stage(
                "fix",
                "AI Auto-Fix",
                "skipped",
                (
                    "No vulnerable source files "
                    "require remediation."
                ),
            )

        else:

            # =================================================
            # MAXIMUM UNIQUE FILE LIMIT
            # =================================================

            files_to_fix = (
                grouped_findings[
                    :MAX_AUTO_FIXES
                ]
            )


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

                    "original_path": (
                        repository_path
                    ),

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


                # =============================================
                # INVALID PATH
                # =============================================

                if not repository_path:

                    fix_result[
                        "error"
                    ] = (
                        "Finding does not contain "
                        "a valid repository path."
                    )

                    fixes.append(
                        clean_fix_result_for_response(
                            fix_result
                        )
                    )

                    continue


                # =============================================
                # READ COMPLETE SOURCE FILE
                # =============================================

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
                        clean_fix_result_for_response(
                            fix_result
                        )
                    )

                    continue


                # =============================================
                # PREPARE VULNERABILITY DATA
                # =============================================

                vulnerability_for_ai = (
                    safe_finding_copy(
                        grouped_finding
                    )
                )


                vulnerability_for_ai[
                    "path"
                ] = repository_path


                # =============================================
                # ONE GROQ CALL PER UNIQUE FILE
                # =============================================

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


                    fixed_code = (
                        fixed_code.strip()
                    )


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


            # =================================================
            # MARK REMAINING UNIQUE FILES AS SKIPPED
            # =================================================

            if (
                len(grouped_findings)
                > MAX_AUTO_FIXES
            ):

                for skipped_group in (
                    grouped_findings[
                        MAX_AUTO_FIXES:
                    ]
                ):

                    skipped_path = str(
                        skipped_group.get(
                            "path",
                            "",
                        )
                    ).strip()


                    fixes.append(
                        {
                            "success": False,

                            "finding_index": -1,

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


            stages[14] = build_stage(
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

        stages[15] = build_stage(
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


        if not isinstance(
            validation_result,
            dict,
        ):

            validation_result = {
                "success": False,

                "status": "attention",

                "message": (
                    "Validation Agent returned "
                    "an invalid response."
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


        ready_artifacts = (
            validation_result.get(
                "ready_artifacts",
                0,
            )
        )


        validation_status = (
            "Validation Agent completed "
            "remediation artifact checks."
        )


        stages[15] = build_stage(
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


            # =================================================
            # SECURITY FINDINGS
            # =================================================

            "findings_count": len(
                all_security_findings
            ),

            "findings": (
                all_security_findings
            ),

            "semgrep_findings_count": (
                len(findings)
            ),

            "secret_findings_count": (
                len(secret_findings)
            ),


            # =================================================
            # PHASE 5 AGENTS
            # =================================================

            "repository_understanding": (
                repository_understanding
            ),

            "secret_detection": (
                secret_detection
            ),

            # =================================================
            # ML SECURITY INTELLIGENCE
            # =================================================

            "ml_triage": ml_triage_result,
            "ml_classification": ml_classification_result,
            "ml_severity": ml_severity_result,
            "ml_priority": ml_priority_result,
            "ml_code_context": ml_code_context_result,
            "ml_similarity": ml_similarity_result,
            "ml_fix_recommendation": ml_fix_recommendation_result,

            "compliance": (
                compliance_result
            ),


            # =================================================
            # RISK
            # =================================================

            "risk_assessments": (
                risk_assessments
            ),

            "overall_risk": (
                overall_risk
            ),


            # =================================================
            # AI
            # =================================================

            "ai_analysis": "",

            "fixes": fixes,


            # =================================================
            # VALIDATION
            # =================================================

            "validation": (
                validation_result
            ),

            "validation_status": (
                validation_status
            ),


            # =================================================
            # PIPELINE
            # =================================================

            "pipeline_status": (
                "completed"
            ),

            "stages": stages,


            # =================================================
            # AUTO-FIX INFORMATION
            # =================================================

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
            ),


            # =================================================
            # GROQ INFORMATION
            # =================================================

            "groq_used_for_report": False,

            "groq_used_for_auto_fix": True,


            # =================================================
            # SECURITY / PRIVACY
            # =================================================

            "second_scan_after_fix": False,

            "original_repository_modified": False,


            # =================================================
            # MESSAGE
            # =================================================

            "message": (
                "Autonomous Phase 7 repository security analysis completed."
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


        risk_assessments = (
            assess_findings(
                findings
            )
        )


        overall_risk = (
            calculate_overall_risk(
                risk_assessments
            )
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

            "overall_risk": (
                overall_risk
            ),
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
# PHASE 5 INFORMATION
# ============================================================

@app.get("/phase5")
async def phase5_info():

    return {

        "success": True,

        "title": (
            "A Multi-Agent System for Automated "
            "Software Repository Security Analysis"
        ),

        "version": APP_VERSION,

        "phase": "Phase 7 - ML Security Intelligence",


        "architecture": [

            "Repository Upload",

            "Safe ZIP Extraction",

            "Repository Understanding Agent",

            "Semgrep Security Detection",

            "Secret Detection Agent",

            "Combined Security Findings",

            "Risk Assessment",

            "Compliance Agent - OWASP Top 10",

            "AI Auto-Fix",

            "Validation Agent",

            "Role-Based Reporting",

            "Automatic Email Delivery",

            "Manual Security Report Download",

            "Manual Fixed Repository Download",
        ],


        "agents": {

            "repository_understanding": True,

            "secret_detection": True,

            "compliance_mapping": True,

            "risk_assessment": True,

            "ai_auto_fix": True,

            "validation": True,
            "ml_triage": True,
            "ml_classification": True,
            "ml_severity": True,
            "ml_priority": True,
            "ml_code_context": True,
            "ml_similarity": True,
            "ml_fix_recommendation": True,
        },


        "groq_used_for_report": False,

        "groq_used_for_auto_fix": True,

        "max_unique_files_for_auto_fix": (
            MAX_AUTO_FIXES
        ),

        "second_scan_after_fix": False,

        "original_repository_modified": False,
    }


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

@app.get("/phase4")
async def phase4_info():

    return {

        "success": True,

        "message": (
            "Phase 4 architecture is preserved "
            "inside the Phase 7 implementation."
        ),

        "current_phase": "Phase 7 - ML Security Intelligence",

        "phase4_core_pipeline": [

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

        "phase5_additions": [

            "Repository Understanding Agent",

            "Secret Detection Agent",

            "Compliance Agent",

            "OWASP Top 10 Mapping",
        ],

        "groq_used_for_report": False,

        "groq_used_for_auto_fix": True,

        "max_unique_files_for_auto_fix": (
            MAX_AUTO_FIXES
        ),

        "second_scan_after_fix": False,

        "original_repository_modified": False,
    }