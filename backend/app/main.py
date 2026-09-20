from __future__ import annotations

import io
import json
import shutil
import threading
import uuid
import zipfile
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from app.agents.auto_fix_agent import generate_fix
from app.agents.compliance_agent import run_compliance_agent
from app.agents.dependency_vulnerability_agent import (
    run_dependency_vulnerability_agent,
)
from app.agents.ml_classification_agent import run_ml_classification
from app.agents.ml_code_context_agent import run_ml_code_context
from app.agents.ml_fix_recommendation_agent import run_ml_fix_recommendation
from app.agents.ml_priority_agent import run_ml_priority
from app.agents.ml_severity_agent import run_ml_severity
from app.agents.ml_similarity_agent import run_ml_similarity
from app.agents.ml_triage_agent import run_ml_triage
from app.agents.repository_understanding_agent import (
    run_repository_understanding,
)
from app.agents.secret_detection_agent import run_secret_detection
from app.agents.validation_agent import run_validation_agent
from app.finding_id import assign_finding_id, assign_finding_ids, get_finding_id
from app.database import Base, engine
from app.risk_engine import assess_findings, calculate_overall_risk
from app.scanner import extract_zip_to_temp, run_semgrep_scan


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

APP_VERSION = "7.2.1"

MAX_UPLOAD_SIZE = 50 * 1024 * 1024
MAX_GROQ_FILES = 3
MAX_SOURCE_FILE_SIZE = 10 * 1024 * 1024

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SentinelForge AI",
    version=APP_VERSION,
    description="Multi-agent software repository security analysis backend",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sentinelforge-ai.vercel.app",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# IN-MEMORY SCAN STORAGE
# ============================================================

SCAN_PROGRESS: dict[str, dict[str, Any]] = {}
SCAN_PROGRESS_LOCK = threading.Lock()

SCAN_ARTIFACTS: dict[str, dict[str, Any]] = {}
SCAN_ARTIFACTS_LOCK = threading.Lock()


# ============================================================
# GENERAL HELPERS
# ============================================================

def normalize_role(role: str | None) -> str:
    value = (role or "student").strip().lower()

    if value not in {"student", "developer", "admin"}:
        return "student"

    return value


def validate_email(email: str | None) -> bool:
    if not email:
        return False

    email = email.strip()

    if "@" not in email:
        return False

    domain = email.split("@")[-1]

    return "." in domain


def safe_json(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


def safe_finding_copy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return dict(value)


def get_finding_line(finding: dict[str, Any]) -> int | None:
    start = finding.get("start")

    if isinstance(start, dict) and start.get("line") is not None:
        value = start.get("line")
    else:
        value = (
            finding.get("line")
            or finding.get("start_line")
        )

    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# ============================================================
# STAGE / PROGRESS HELPERS
# ============================================================

def build_stage(
    stage_id: str,
    name: str,
    status: str = "pending",
    progress: float = 0,
    message: str = "",
) -> dict[str, Any]:
    return {
        "id": stage_id,
        "name": name,
        "status": status,
        "progress": progress,
        "message": message,
    }


def build_initial_stages() -> list[dict[str, Any]]:
    definitions = [
        ("repository", "Repository Upload"),
        ("extract", "Secure Extraction"),
        ("understanding", "Repository Understanding"),
        ("semgrep", "Semgrep Detection"),
        ("secret", "Secret Detection"),
        ("dependency", "Dependency Vulnerability"),
        ("ml_triage", "ML Vulnerability Triage"),
        ("ml_classification", "ML Classification"),
        ("ml_severity", "ML Severity Prediction"),
        ("ml_priority", "ML Priority Prediction"),
        ("ml_code_context", "ML Code Context"),
        ("ml_similarity", "ML Duplicate Similarity"),
        ("ml_fix_recommendation", "ML Fix Recommendation"),
        ("risk", "Risk Assessment"),
        ("compliance", "Compliance Mapping"),
        ("fix", "AI Auto-Fix"),
        ("validation", "Fix Validation"),
        ("report", "Security Report"),
    ]

    return [
        build_stage(stage_id, name)
        for stage_id, name in definitions
    ]


def _update_progress(
    scan_id: str,
    *,
    stage_id: str | None = None,
    status: str | None = None,
    progress: float | None = None,
    message: str | None = None,
    data: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    with SCAN_PROGRESS_LOCK:
        state = SCAN_PROGRESS.get(scan_id)

        if not state:
            return

        stages = state.get("stages", [])

        if stage_id:
            for stage in stages:
                if stage.get("id") == stage_id:
                    if status is not None:
                        stage["status"] = status

                    if progress is not None:
                        stage["progress"] = progress

                    if message is not None:
                        stage["message"] = message

                    break

        completed_count = sum(
            1
            for stage in stages
            if stage.get("status") == "completed"
        )

        running_count = sum(
            1
            for stage in stages
            if stage.get("status") == "running"
        )

        total_count = max(len(stages), 1)

        overall = (
            completed_count
            + (0.5 if running_count else 0)
        ) / total_count * 100

        state["progress"] = round(
            min(overall, 100),
            2,
        )

        if message is not None:
            state["message"] = message

        if data is not None:
            state["data"] = safe_json(data)

        if error is not None:
            state["error"] = str(error)
            state["status"] = "error"


def _start_stage(
    scan_id: str,
    stage_id: str,
    message: str,
) -> None:
    _update_progress(
        scan_id,
        stage_id=stage_id,
        status="running",
        progress=0,
        message=message,
    )


def _complete_stage(
    scan_id: str,
    stage_id: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    _update_progress(
        scan_id,
        stage_id=stage_id,
        status="completed",
        progress=100,
        message=message,
        data=data,
    )


def _fail_scan(
    scan_id: str,
    error_message: str,
) -> None:
    with SCAN_PROGRESS_LOCK:
        state = SCAN_PROGRESS.get(scan_id)

        if not state:
            return

        state["status"] = "error"
        state["error"] = str(error_message)
        state["message"] = "Security analysis failed."

        for stage in state.get("stages", []):
            if stage.get("status") == "running":
                stage["status"] = "failed"
                stage["progress"] = 0
                stage["message"] = str(error_message)


def _get_stage_snapshot(
    scan_id: str,
) -> list[dict[str, Any]]:
    with SCAN_PROGRESS_LOCK:
        state = SCAN_PROGRESS.get(scan_id)

        if not state:
            return []

        return safe_json(
            state.get("stages", [])
        )


# ============================================================
# SOURCE FILE HELPERS
# ============================================================

def read_complete_source_file(
    repository_path: Path,
    relative_path: str,
) -> str:
    safe_relative = Path(
        str(relative_path).replace("\\", "/")
    )

    if safe_relative.is_absolute():
        return ""

    if ".." in safe_relative.parts:
        return ""

    candidate = (
        repository_path / safe_relative
    ).resolve()

    root = repository_path.resolve()

    try:
        candidate.relative_to(root)
    except ValueError:
        return ""

    if not candidate.is_file():
        return ""

    try:
        if candidate.stat().st_size > MAX_SOURCE_FILE_SIZE:
            return ""

        return candidate.read_text(
            encoding="utf-8",
            errors="replace",
        )

    except Exception:
        return ""


def group_findings_by_file(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        path = (
            finding.get("path")
            or finding.get("file")
            or finding.get("filename")
            or "unknown"
        )

        path = str(path).replace("\\", "/")

        grouped.setdefault(
            path,
            [],
        ).append(finding)

    return grouped


# ============================================================
# ML HELPERS
# ============================================================

def build_ml_finding(
    finding: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    extra = finding.get("extra")

    if not isinstance(extra, dict):
        extra = {}

    metadata = extra.get("metadata")

    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "finding_id": get_finding_id(finding),
        "finding_index": index,
        "check_id": (
            finding.get("check_id")
            or finding.get("rule_id")
        ),
        "rule_id": (
            finding.get("rule_id")
            or finding.get("check_id")
        ),
        "path": (
            finding.get("path")
            or finding.get("file")
        ),
        "line": get_finding_line(finding),
        "message": (
            extra.get("message")
            or finding.get("message")
        ),
        "severity": (
            extra.get("severity")
            or finding.get("severity")
        ),
        "cwe": (
            metadata.get("cwe")
            or finding.get("cwe")
        ),
        "owasp": (
            metadata.get("owasp")
            or finding.get("owasp")
        ),
        "source_code": finding.get(
            "source_code",
            "",
        ),
        "code_context": finding.get(
            "code_context",
            "",
        ),
    }


def build_ml_error(
    name: str,
    error: Exception,
) -> dict[str, Any]:
    return {
        "agent": name,
        "success": False,
        "error": str(error),
        "results": [],
    }


def _result_items(
    result: Any,
) -> list[dict[str, Any]]:
    if isinstance(result, dict):
        items = result.get("results")

        if isinstance(items, list):
            return [
                item
                for item in items
                if isinstance(item, dict)
            ]

    if isinstance(result, list):
        return [
            item
            for item in result
            if isinstance(item, dict)
        ]

    return []


def _result_map(
    result: Any,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[int, dict[str, Any]],
]:
    by_id: dict[str, dict[str, Any]] = {}
    by_index: dict[int, dict[str, Any]] = {}

    for item in _result_items(result):
        finding_id = (
            item.get("finding_id")
            or item.get("findingId")
            or item.get("id")
        )

        if finding_id:
            by_id[str(finding_id)] = item

        index = item.get("finding_index")

        if index is not None:
            try:
                by_index[int(index)] = item
            except (TypeError, ValueError):
                pass

    return by_id, by_index


def _lookup_result(
    result: Any,
    finding: dict[str, Any],
    fallback_index: int | None = None,
) -> dict[str, Any] | None:
    by_id, by_index = _result_map(result)

    finding_id = get_finding_id(finding)

    if finding_id and finding_id in by_id:
        return by_id[finding_id]

    index = finding.get("finding_index")

    if index is not None:
        try:
            if int(index) in by_index:
                return by_index[int(index)]
        except (TypeError, ValueError):
            pass

    if fallback_index is not None:
        if fallback_index in by_index:
            return by_index[fallback_index]

    return None


def attach_ml_intelligence(
    findings: list[dict[str, Any]],
    ml_results: dict[str, Any],
    risk_assessments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    risk_by_id: dict[str, dict[str, Any]] = {}

    for assessment in risk_assessments:
        if not isinstance(assessment, dict):
            continue

        finding_id = (
            assessment.get("finding_id")
            or assessment.get("findingId")
            or assessment.get("id")
        )

        if finding_id:
            risk_by_id[str(finding_id)] = assessment

    output: list[dict[str, Any]] = []

    for index, original in enumerate(findings):
        finding = safe_finding_copy(original)

        finding_id = get_finding_id(finding)

        if not finding_id:
            assign_finding_id(
                finding,
                index + 1,
            )

            finding_id = get_finding_id(
                finding
            )

        finding["finding_index"] = index

        ml_bundle: dict[str, Any] = {}

        for key, result in ml_results.items():
            if not key.startswith("ml_"):
                continue

            if key == "ml_similarity":
                continue

            item = _lookup_result(
                result,
                finding,
                index,
            )

            if item:
                copied_item = safe_finding_copy(item)

                ml_bundle[key] = copied_item
                finding[key] = copied_item

        if finding_id and finding_id in risk_by_id:
            finding["risk_assessment"] = (
                safe_finding_copy(
                    risk_by_id[finding_id]
                )
            )

            finding["official_risk"] = (
                safe_finding_copy(
                    risk_by_id[finding_id]
                )
            )

        finding["ml_results"] = ml_bundle

        output.append(finding)

    return output


def build_ml_results_summary(
    ml_results: dict[str, Any],
) -> dict[str, Any]:
    summary: dict[str, Any] = {}

    for name, result in ml_results.items():
        if not isinstance(result, dict):
            summary[name] = result
            continue

        items = _result_items(result)

        summary[name] = {
            "success": result.get(
                "success",
                True,
            ),
            "count": len(items),
            "results": items,
            "error": result.get("error"),
        }

    return summary


# ============================================================
# SIMILARITY HELPERS
# ============================================================

def build_similarity_pairs(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []

    for first_index in range(len(findings)):
        for second_index in range(
            first_index + 1,
            len(findings),
        ):
            pairs.append(
                {
                    "finding_1": safe_finding_copy(
                        findings[first_index]
                    ),
                    "finding_2": safe_finding_copy(
                        findings[second_index]
                    ),
                    "finding_1_index": first_index,
                    "finding_2_index": second_index,
                }
            )

    return pairs


def label_similarity_pairs(
    similarity_result: Any,
    findings: list[dict[str, Any]],
) -> Any:
    if not isinstance(similarity_result, dict):
        return similarity_result

    output = safe_finding_copy(
        similarity_result
    )

    results = output.get("results")

    if not isinstance(results, list):
        return output

    labeled: list[dict[str, Any]] = []

    for item in results:
        if not isinstance(item, dict):
            continue

        row = safe_finding_copy(item)

        first_index = row.get(
            "finding_1_index"
        )

        second_index = row.get(
            "finding_2_index"
        )

        try:
            first_index = int(first_index)
        except (TypeError, ValueError):
            first_index = None

        try:
            second_index = int(second_index)
        except (TypeError, ValueError):
            second_index = None

        if (
            first_index is not None
            and 0 <= first_index < len(findings)
        ):
            row["finding_1_id"] = (
                get_finding_id(
                    findings[first_index]
                )
            )

        if (
            second_index is not None
            and 0 <= second_index < len(findings)
        ):
            row["finding_2_id"] = (
                get_finding_id(
                    findings[second_index]
                )
            )

        if "similarity_probability" in row:
            try:
                row["similarity_percentage"] = round(
                    float(
                        row["similarity_probability"]
                    ) * 100,
                    2,
                )
            except (TypeError, ValueError):
                pass

        if "prediction" in row:
            value = row["prediction"]

            if isinstance(value, str):
                row["duplicate"] = (
                    value.strip().lower()
                    in {
                        "true",
                        "1",
                        "yes",
                        "duplicate",
                    }
                )
            else:
                row["duplicate"] = bool(value)

        labeled.append(row)

    output["results"] = labeled

    return output


# ============================================================
# FIXED ZIP HELPERS
# ============================================================

def _safe_zip_path(
    path_value: Any,
) -> str | None:
    if not path_value:
        return None

    value = str(path_value).replace(
        "\\",
        "/",
    ).strip()

    if not value:
        return None

    path = Path(value)

    if path.is_absolute():
        return None

    if ".." in path.parts:
        return None

    return str(path).replace(
        "\\",
        "/",
    )


def apply_fixes_to_zip(
    original_zip_bytes: bytes,
    fixes: list[dict[str, Any]],
    report_result: dict[str, Any],
) -> bytes:
    output_buffer = io.BytesIO()

    fixed_files: dict[str, str] = {}

    for fix in fixes:
        if not isinstance(fix, dict):
            continue

        if not fix.get("success"):
            continue

        fixed_code = fix.get("fixed_code")

        if not isinstance(fixed_code, str):
            continue

        original_path = (
            fix.get("original_path")
            or fix.get("path")
            or fix.get("file")
        )

        safe_path = _safe_zip_path(
            original_path
        )

        if safe_path:
            fixed_files[safe_path] = fixed_code

    with zipfile.ZipFile(
        io.BytesIO(original_zip_bytes),
        "r",
    ) as source_zip:

        with zipfile.ZipFile(
            output_buffer,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as output_zip:

            existing_names: set[str] = set()

            for info in source_zip.infolist():
                safe_name = _safe_zip_path(
                    info.filename
                )

                if not safe_name:
                    continue

                existing_names.add(safe_name)

                if info.is_dir():
                    output_zip.writestr(
                        info,
                        b"",
                    )
                    continue

                if safe_name in fixed_files:
                    output_zip.writestr(
                        safe_name,
                        fixed_files[safe_name].encode(
                            "utf-8"
                        ),
                    )
                else:
                    output_zip.writestr(
                        info,
                        source_zip.read(
                            info.filename
                        ),
                    )

            for path, content in fixed_files.items():
                if path not in existing_names:
                    output_zip.writestr(
                        path,
                        content.encode(
                            "utf-8"
                        ),
                    )

            manifest = {
                "application": "SentinelForge AI",
                "app_version": APP_VERSION,
                "description": (
                    "Security analysis and AI-assisted "
                    "remediation manifest."
                ),
                "successful_fixes": [
                    {
                        "finding_id": fix.get(
                            "finding_id"
                        ),
                        "original_path": fix.get(
                            "original_path"
                        ),
                        "success": True,
                        "fixed_code_length": (
                            len(
                                fix.get(
                                    "fixed_code",
                                    "",
                                )
                            )
                            if isinstance(
                                fix.get(
                                    "fixed_code"
                                ),
                                str,
                            )
                            else 0
                        ),
                    }
                    for fix in fixes
                    if (
                        isinstance(fix, dict)
                        and fix.get("success")
                    )
                ],
                "validation": safe_json(
                    report_result.get(
                        "validation",
                        {},
                    )
                ),
                "overall_risk": report_result.get(
                    "overall_risk"
                ),
                "findings_count": report_result.get(
                    "findings_count",
                    0,
                ),
                "secret_count": report_result.get(
                    "secret_count",
                    0,
                ),
                "dependency_count": report_result.get(
                    "dependency_count",
                    0,
                ),
            }

            output_zip.writestr(
                "security-analysis-manifest.json",
                json.dumps(
                    manifest,
                    indent=2,
                    ensure_ascii=False,
                ).encode("utf-8"),
            )

    output_buffer.seek(0)

    return output_buffer.getvalue()


# ============================================================
# MAIN SCAN PIPELINE
# ============================================================

def run_scan_pipeline(
    scan_id: str,
    zip_bytes: bytes,
    filename: str,
    role: str,
    email: str,
) -> None:

    repository_path: Path | None = None

    findings: list[dict[str, Any]] = []
    secret_findings: list[dict[str, Any]] = []

    dependency_analysis: Any = {
        "success": True,
        "vulnerabilities": [],
        "count": 0,
    }

    secret_analysis: Any = {
        "success": True,
        "secrets": [],
        "count": 0,
    }

    ml_results: dict[str, Any] = {}

    risk_assessments: list[dict[str, Any]] = []

    compliance_result: Any = {
        "success": True,
        "results": [],
    }

    fixes: list[dict[str, Any]] = []

    validation_results: Any = {
        "success": True,
        "results": [],
    }

    repository_understanding: Any = {}

    overall_risk = "LOW"

    groq_auto_fix_attempted = False

    try:

        # ====================================================
        # 1. REPOSITORY
        # ====================================================

        _start_stage(
            scan_id,
            "repository",
            "Repository received and scan initialized.",
        )

        _complete_stage(
            scan_id,
            "repository",
            "Repository upload validated.",
            {
                "filename": filename,
                "role": role,
            },
        )

        # ====================================================
        # 2. EXTRACTION
        # ====================================================

        _start_stage(
            scan_id,
            "extract",
            "Securely extracting repository ZIP.",
        )

        repository_path = extract_zip_to_temp(
            io.BytesIO(zip_bytes)
        )

        _complete_stage(
            scan_id,
            "extract",
            "Repository extracted securely.",
        )

        # ====================================================
        # 3. REPOSITORY UNDERSTANDING
        # ====================================================

        _start_stage(
            scan_id,
            "understanding",
            "Understanding repository structure.",
        )

        try:
            repository_understanding = safe_json(
                run_repository_understanding(
                    repository_path
                )
            )
        except Exception as exc:
            repository_understanding = {
                "success": False,
                "error": str(exc),
            }

        _complete_stage(
            scan_id,
            "understanding",
            "Repository understanding completed.",
            {
                "repository_understanding":
                    repository_understanding
            },
        )

        # ====================================================
        # 4. SEMGREP
        # ====================================================

        _start_stage(
            scan_id,
            "semgrep",
            "Running Semgrep security detection.",
        )

        raw_findings = run_semgrep_scan(
            repository_path
        )

        findings = []

        for index, raw_finding in enumerate(
            raw_findings or [],
            start=1,
        ):
            finding = safe_finding_copy(
                raw_finding
            )

            path_value = (
                finding.get("path")
                or finding.get("file")
            )

            if path_value:
                finding["path"] = str(
                    path_value
                ).replace(
                    "\\",
                    "/",
                )

            assign_finding_id(
                finding,
                index,
            )

            finding["finding_index"] = (
                index - 1
            )

            line = get_finding_line(
                finding
            )

            if line is not None:
                finding["line"] = line

            if not finding.get("source_code"):
                path_value = finding.get(
                    "path"
                )

                if path_value:
                    finding["source_code"] = (
                        read_complete_source_file(
                            repository_path,
                            str(path_value),
                        )
                    )

            findings.append(finding)

        _complete_stage(
            scan_id,
            "semgrep",
            (
                "Semgrep detection completed with "
                f"{len(findings)} finding(s)."
            ),
            {
                "findings_count": len(findings),
                "findings": findings,
            },
        )

        # ====================================================
        # 5. SECRET DETECTION
        # ====================================================

        _start_stage(
            scan_id,
            "secret",
            "Scanning for exposed secrets and credentials.",
        )

        try:
            secret_analysis = safe_json(
                run_secret_detection(
                    repository_path
                )
            )
        except Exception as exc:
            secret_analysis = {
                "success": False,
                "error": str(exc),
                "secrets": [],
                "count": 0,
            }

        if isinstance(
            secret_analysis,
            dict,
        ):
            secret_findings = (
                secret_analysis.get("secrets")
                or secret_analysis.get("findings")
                or []
            )

        elif isinstance(
            secret_analysis,
            list,
        ):
            secret_findings = secret_analysis

        else:
            secret_findings = []

        secret_findings = [
            safe_finding_copy(item)
            for item in secret_findings
            if isinstance(item, dict)
        ]

        assign_finding_ids(
            secret_findings,
            start_index=len(findings) + 1,
        )

        for index, finding in enumerate(
            secret_findings
        ):
            finding["finding_index"] = (
                len(findings) + index
            )

        if isinstance(
            secret_analysis,
            dict,
        ):
            secret_analysis["secrets"] = (
                secret_findings
            )

            secret_analysis["count"] = (
                len(secret_findings)
            )

        _complete_stage(
            scan_id,
            "secret",
            (
                "Secret detection completed with "
                f"{len(secret_findings)} finding(s)."
            ),
            {
                "secret_analysis":
                    secret_analysis
            },
        )

        # ====================================================
        # 6. DEPENDENCY VULNERABILITY
        # ====================================================

        _start_stage(
            scan_id,
            "dependency",
            (
                "Checking project dependencies for "
                "known vulnerabilities."
            ),
        )

        try:
            dependency_analysis = safe_json(
                run_dependency_vulnerability_agent(
                    repository_path
                )
            )
        except Exception as exc:
            dependency_analysis = {
                "success": False,
                "error": str(exc),
                "vulnerabilities": [],
                "count": 0,
            }

        _complete_stage(
            scan_id,
            "dependency",
            "Dependency vulnerability analysis completed.",
            {
                "dependency_analysis":
                    dependency_analysis
            },
        )

        # ====================================================
        # ML INPUT
        # ====================================================

        ml_findings = [
            build_ml_finding(
                finding,
                index,
            )
            for index, finding in enumerate(
                findings
            )
        ]

        # ====================================================
        # 7. ML TRIAGE
        # ====================================================

        _start_stage(
            scan_id,
            "ml_triage",
            "Running ML vulnerability triage.",
        )

        try:
            ml_results["ml_triage"] = safe_json(
                run_ml_triage(
                    ml_findings
                )
            )
        except Exception as exc:
            ml_results["ml_triage"] = build_ml_error(
                "ml_triage",
                exc,
            )

        _complete_stage(
            scan_id,
            "ml_triage",
            "ML triage completed.",
        )

        # ====================================================
        # 8. ML CLASSIFICATION
        # ====================================================

        _start_stage(
            scan_id,
            "ml_classification",
            "Classifying vulnerability types.",
        )

        try:
            ml_results["ml_classification"] = safe_json(
                run_ml_classification(
                    ml_findings
                )
            )
        except Exception as exc:
            ml_results["ml_classification"] = build_ml_error(
                "ml_classification",
                exc,
            )

        _complete_stage(
            scan_id,
            "ml_classification",
            "ML classification completed.",
        )

        # ====================================================
        # 9. ML SEVERITY
        # ====================================================

        _start_stage(
            scan_id,
            "ml_severity",
            "Predicting vulnerability severity.",
        )

        try:
            ml_results["ml_severity"] = safe_json(
                run_ml_severity(
                    ml_findings
                )
            )
        except Exception as exc:
            ml_results["ml_severity"] = build_ml_error(
                "ml_severity",
                exc,
            )

        _complete_stage(
            scan_id,
            "ml_severity",
            "ML severity prediction completed.",
        )

        # ====================================================
        # 10. ML PRIORITY
        # ====================================================

        _start_stage(
            scan_id,
            "ml_priority",
            "Predicting remediation priority.",
        )

        try:
            ml_results["ml_priority"] = safe_json(
                run_ml_priority(
                    ml_findings
                )
            )
        except Exception as exc:
            ml_results["ml_priority"] = build_ml_error(
                "ml_priority",
                exc,
            )

        _complete_stage(
            scan_id,
            "ml_priority",
            "ML priority prediction completed.",
        )

        # ====================================================
        # 11. ML CODE CONTEXT
        # ====================================================

        _start_stage(
            scan_id,
            "ml_code_context",
            "Analyzing vulnerable code context.",
        )

        try:
            ml_results["ml_code_context"] = safe_json(
                run_ml_code_context(
                    ml_findings
                )
            )
        except Exception as exc:
            ml_results["ml_code_context"] = build_ml_error(
                "ml_code_context",
                exc,
            )

        _complete_stage(
            scan_id,
            "ml_code_context",
            "ML code-context analysis completed.",
        )

        # ====================================================
        # 12. ML SIMILARITY
        # ====================================================

        _start_stage(
            scan_id,
            "ml_similarity",
            "Checking for duplicate or similar findings.",
        )

        try:
            similarity_pairs = build_similarity_pairs(
                ml_findings
            )

            similarity_result = safe_json(
                run_ml_similarity(
                    similarity_pairs
                )
            )

            similarity_result = label_similarity_pairs(
                similarity_result,
                findings,
            )

            ml_results["ml_similarity"] = (
                similarity_result
            )

        except Exception as exc:
            similarity_result = build_ml_error(
                "ml_similarity",
                exc,
            )

            ml_results["ml_similarity"] = (
                similarity_result
            )

        _complete_stage(
            scan_id,
            "ml_similarity",
            "Duplicate similarity analysis completed.",
            {
                "ml_similarity":
                    similarity_result
            },
        )

        # ====================================================
        # 13. ML FIX RECOMMENDATION
        # ====================================================

        _start_stage(
            scan_id,
            "ml_fix_recommendation",
            "Generating ML remediation recommendations.",
        )

        try:
            ml_results[
                "ml_fix_recommendation"
            ] = safe_json(
                run_ml_fix_recommendation(
                    ml_findings
                )
            )

        except Exception as exc:
            ml_results[
                "ml_fix_recommendation"
            ] = build_ml_error(
                "ml_fix_recommendation",
                exc,
            )

        _complete_stage(
            scan_id,
            "ml_fix_recommendation",
            "ML fix recommendations completed.",
        )

        # ====================================================
        # 14. OFFICIAL RISK ASSESSMENT
        # ====================================================

        all_security_findings = (
            findings + secret_findings
        )

        _start_stage(
            scan_id,
            "risk",
            "Calculating official security risk.",
        )

        try:
            risk_result = safe_json(
                assess_risk(
                    all_security_findings
                )
            )

            if isinstance(
                risk_result,
                dict,
            ):
                risk_assessments = (
                    risk_result.get(
                        "assessments"
                    )
                    or risk_result.get(
                        "risk_assessments"
                    )
                    or risk_result.get(
                        "results"
                    )
                    or []
                )

                overall_risk = (
                    risk_result.get(
                        "overall_risk"
                    )
                    or risk_result.get(
                        "risk_level"
                    )
                    or "LOW"
                )

            elif isinstance(
                risk_result,
                list,
            ):
                risk_assessments = risk_result
                overall_risk = "LOW"

        except Exception as exc:
            risk_assessments = []

            overall_risk = "LOW"

            # Keep scan running rather than killing the entire
            # repository analysis because of risk-agent failure.
            risk_error = {
                "success": False,
                "error": str(exc),
            }

        # Attach ML and official risk before Auto-Fix.
        findings = attach_ml_intelligence(
            findings,
            ml_results,
            risk_assessments,
        )

        secret_findings = attach_ml_intelligence(
            secret_findings,
            {},
            risk_assessments,
        )

        all_security_findings = (
            findings + secret_findings
        )

        risk_stage_data: dict[str, Any] = {
            "overall_risk": overall_risk,
            "risk_assessments": risk_assessments,
        }

        if "risk_error" in locals():
            risk_stage_data["error"] = risk_error

        _complete_stage(
            scan_id,
            "risk",
            (
                "Risk assessment completed. "
                f"Overall risk: {overall_risk}."
            ),
            risk_stage_data,
        )

        # ====================================================
        # 15. COMPLIANCE
        # ====================================================

        _start_stage(
            scan_id,
            "compliance",
            "Mapping findings to security compliance references.",
        )

        try:
            try:
                compliance_result = safe_json(
                    run_compliance_agent(
                        findings=all_security_findings,
                        risk_assessments=risk_assessments,
                    )
                )
            except TypeError:
                compliance_result = safe_json(
                    run_compliance_agent(
                        all_security_findings,
                        risk_assessments,
                    )
                )

        except Exception as exc:
            compliance_result = {
                "success": False,
                "error": str(exc),
                "results": [],
            }

        _complete_stage(
            scan_id,
            "compliance",
            "Compliance mapping completed.",
            {
                "compliance":
                    compliance_result
            },
        )

        # ====================================================
        # 16. AI AUTO-FIX
        # ====================================================

        _start_stage(
            scan_id,
            "fix",
            "Generating AI-assisted fixes for eligible findings.",
        )

        grouped_findings = group_findings_by_file(
            all_security_findings
        )

        eligible_files = [
            path
            for path in grouped_findings
            if path and path != "unknown"
        ][:MAX_GROQ_FILES]

        if not eligible_files:

            _complete_stage(
                scan_id,
                "fix",
                "No eligible findings were available for AI Auto-Fix.",
                {
                    "fixes": [],
                    "groq_auto_fix_attempted": False,
                },
            )

        else:

            for path in eligible_files:

                file_findings = grouped_findings[path]

                full_source_code = read_complete_source_file(
                    repository_path,
                    path,
                )

                if not full_source_code:

                    fixes.append(
                        {
                            "success": False,
                            "finding_id": (
                                get_finding_id(
                                    file_findings[0]
                                )
                                if file_findings
                                else None
                            ),
                            "original_path": path,
                            "error": (
                                "Source file could not be read."
                            ),
                        }
                    )

                    continue

                primary_finding = file_findings[0]

                primary_id = get_finding_id(
                    primary_finding
                )

                vulnerability_for_ai = safe_finding_copy(
                    primary_finding
                )

                ml_bundle: dict[str, Any] = {}

                for ml_key, ml_result in ml_results.items():

                    if ml_key == "ml_similarity":
                        continue

                    item = _lookup_result(
                        ml_result,
                        primary_finding,
                    )

                    if item:
                        copied_item = safe_finding_copy(
                            item
                        )

                        vulnerability_for_ai[
                            ml_key
                        ] = copied_item

                        ml_bundle[
                            ml_key
                        ] = copied_item

                vulnerability_for_ai[
                    "ml_results"
                ] = ml_bundle

                for assessment in risk_assessments:

                    if not isinstance(
                        assessment,
                        dict,
                    ):
                        continue

                    assessment_id = (
                        assessment.get(
                            "finding_id"
                        )
                        or assessment.get(
                            "findingId"
                        )
                        or assessment.get(
                            "id"
                        )
                    )

                    if (
                        primary_id
                        and assessment_id
                        and str(
                            assessment_id
                        )
                        == str(
                            primary_id
                        )
                    ):
                        vulnerability_for_ai[
                            "risk_assessment"
                        ] = safe_finding_copy(
                            assessment
                        )

                        vulnerability_for_ai[
                            "official_risk"
                        ] = safe_finding_copy(
                            assessment
                        )

                        break

                vulnerability_for_ai[
                    "related_findings"
                ] = [
                    safe_finding_copy(item)
                    for item in file_findings
                ]

                vulnerability_for_ai[
                    "path"
                ] = path

                vulnerability_for_ai[
                    "source_code"
                ] = full_source_code

                groq_auto_fix_attempted = True

                try:

                    fixed_code = generate_fix(
                        vulnerability=(
                            vulnerability_for_ai
                        ),
                        source_code=(
                            full_source_code
                        ),
                    )

                    if isinstance(
                        fixed_code,
                        dict,
                    ):
                        fix_result = safe_finding_copy(
                            fixed_code
                        )
                    else:
                        fix_result = {
                            "success": bool(
                                fixed_code
                            ),
                            "fixed_code": (
                                fixed_code
                                if isinstance(
                                    fixed_code,
                                    str,
                                )
                                else ""
                            ),
                        }

                    fix_result.setdefault(
                        "original_path",
                        path,
                    )

                    fix_result.setdefault(
                        "finding_id",
                        primary_id,
                    )

                    fix_result.setdefault(
                        "original_code",
                        full_source_code,
                    )

                    fix_result.setdefault(
                        "path",
                        path,
                    )

                    fixes.append(
                        fix_result
                    )

                except Exception as exc:

                    fixes.append(
                        {
                            "success": False,
                            "finding_id": primary_id,
                            "original_path": path,
                            "path": path,
                            "error": str(exc),
                        }
                    )

            successful_fix_count = sum(
                1
                for item in fixes
                if (
                    isinstance(item, dict)
                    and item.get("success")
                )
            )

            _complete_stage(
                scan_id,
                "fix",
                (
                    "AI Auto-Fix completed with "
                    f"{successful_fix_count} successful fix(es)."
                ),
                {
                    "fixes": fixes,
                    "groq_auto_fix_attempted":
                        groq_auto_fix_attempted,
                },
            )

        # ====================================================
        # 17. VALIDATION
        # ====================================================

        _start_stage(
            scan_id,
            "validation",
            "Validating generated fixes.",
        )

        try:

            try:
                validation_results = safe_json(
                    run_validation_agent(
                        repository_path=repository_path,
                        fixes=fixes,
                    )
                )

            except TypeError:
                validation_results = safe_json(
                    run_validation_agent(
                        fixes
                    )
                )

        except Exception as exc:

            validation_results = {
                "success": False,
                "error": str(exc),
                "results": [],
            }

        _complete_stage(
            scan_id,
            "validation",
            "Fix validation completed.",
            {
                "validation":
                    validation_results
            },
        )

        # ====================================================
        # 18. FINAL SECURITY REPORT
        # ====================================================

        _start_stage(
            scan_id,
            "report",
            "Preparing final security report data.",
        )

        successful_fixes = sum(
            1
            for item in fixes
            if (
                isinstance(item, dict)
                and item.get("success")
            )
        )

        # IMPORTANT:
        # Capture the actual completed stages instead of
        # returning a new list containing only "pending" stages.
        current_pipeline = _get_stage_snapshot(
            scan_id
        )

        report_result = {
            "success": True,
            "status": "completed",

            "message": (
                "Security analysis completed successfully."
            ),

            "filename": filename,
            "role": role,
            "email": email,

            "repository_understanding":
                repository_understanding,

            "findings_count":
                len(findings),

            "secret_count":
                len(secret_findings),

            "dependency_count": (
                dependency_analysis.get(
                    "count",
                    0,
                )
                if isinstance(
                    dependency_analysis,
                    dict,
                )
                else 0
            ),

            "overall_risk":
                overall_risk,

            "findings":
                findings,

            "secrets":
                secret_findings,

            "secret_analysis":
                secret_analysis,

            "dependency_analysis":
                dependency_analysis,

            "ml_results":
                build_ml_results_summary(
                    ml_results
                ),

            "risk_assessments":
                risk_assessments,

            "compliance":
                compliance_result,

            "fixes":
                fixes,

            "successful_fixes":
                successful_fixes,

            "validation":
                validation_results,

            "groq_auto_fix_attempted":
                groq_auto_fix_attempted,

            "pipeline":
                current_pipeline,

            "app_version":
                APP_VERSION,
        }

        # Mark report stage as completed and put the final
        # report into the progress object.
        _complete_stage(
            scan_id,
            "report",
            "Security report is ready.",
            report_result,
        )

        # Refresh pipeline after report completion.
        report_result["pipeline"] = (
            _get_stage_snapshot(
                scan_id
            )
        )

        # ====================================================
        # STORE DOWNLOAD ARTIFACT
        # ====================================================

        with SCAN_ARTIFACTS_LOCK:
            SCAN_ARTIFACTS[scan_id] = {
                "original_zip":
                    zip_bytes,

                "report":
                    safe_json(
                        report_result
                    ),

                "fixes":
                    safe_json(
                        fixes
                    ),
            }

        # ====================================================
        # FINAL STATE
        # ====================================================

        with SCAN_PROGRESS_LOCK:

            state = SCAN_PROGRESS.get(
                scan_id
            )

            if state:

                state["status"] = "completed"

                state["progress"] = 100

                state["message"] = (
                    "Security analysis completed successfully."
                )

                state["error"] = None

                state["data"] = safe_json(
                    report_result
                )

                # Ensure final pipeline shown by frontend
                # contains actual completed statuses.
                state["stages"] = safe_json(
                    report_result["pipeline"]
                )

    except Exception as exc:

        _fail_scan(
            scan_id,
            str(exc),
        )

    finally:

        if repository_path:

            try:
                shutil.rmtree(
                    repository_path,
                    ignore_errors=True,
                )
            except Exception:
                pass


# ============================================================
# BASIC API
# ============================================================

@app.get("/")
def root() -> dict[str, Any]:
    return {
        "success": True,
        "name": "SentinelForge AI",
        "version": APP_VERSION,
        "message": (
            "Multi-agent repository security "
            "analysis API is running."
        ),
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "success": True,
        "status": "healthy",
        "version": APP_VERSION,
    }


# ============================================================
# START ASYNC SCAN
# ============================================================

@app.post("/scan/start")
async def start_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    role: str = Form("student"),
    email: str = Form(""),
) -> dict[str, Any]:

    normalized_role = normalize_role(
        role
    )

    if not email or not validate_email(
        email
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "A valid email address is required."
            ),
        )

    filename = (
        file.filename
        or "repository.zip"
    )

    if not filename.lower().endswith(
        ".zip"
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Please upload a ZIP repository."
            ),
        )

    zip_bytes = await file.read()

    if not zip_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded ZIP is empty.",
        )

    if len(zip_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=(
                "ZIP exceeds the "
                f"{MAX_UPLOAD_SIZE // (1024 * 1024)} MB "
                "upload limit."
            ),
        )

    # Validate ZIP before starting background processing.
    try:

        with zipfile.ZipFile(
            io.BytesIO(zip_bytes)
        ) as archive:

            bad_file = archive.testzip()

            if bad_file:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Corrupted ZIP entry detected: "
                        f"{bad_file}"
                    ),
                )

    except zipfile.BadZipFile:

        raise HTTPException(
            status_code=400,
            detail=(
                "The uploaded file is not a valid ZIP."
            ),
        )

    scan_id = uuid.uuid4().hex

    with SCAN_PROGRESS_LOCK:

        SCAN_PROGRESS[scan_id] = {
            "scan_id": scan_id,
            "status": "queued",
            "progress": 0,
            "message": "Scan queued.",
            "stages":
                build_initial_stages(),
            "data": None,
            "error": None,
        }

    # IMPORTANT:
    # This is the only async scan architecture used by
    # the current App.jsx.
    background_tasks.add_task(
        run_scan_pipeline,
        scan_id,
        zip_bytes,
        filename,
        normalized_role,
        email.strip(),
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "status": "queued",
        "message": (
            "Security analysis started."
        ),
    }


# ============================================================
# SCAN PROGRESS
# ============================================================

@app.get("/scan/progress/{scan_id}")
def get_scan_progress(
    scan_id: str,
) -> dict[str, Any]:

    with SCAN_PROGRESS_LOCK:

        state = SCAN_PROGRESS.get(
            scan_id
        )

        if not state:

            raise HTTPException(
                status_code=404,
                detail="Scan not found.",
            )

        return safe_json(state)


# ============================================================
# DOWNLOAD FIXED REPOSITORY
# ============================================================

@app.get("/scan/download-fixed/{scan_id}")
def download_fixed_repository(
    scan_id: str,
) -> StreamingResponse:

    with SCAN_ARTIFACTS_LOCK:

        artifact = SCAN_ARTIFACTS.get(
            scan_id
        )

    if not artifact:

        raise HTTPException(
            status_code=404,
            detail=(
                "Fixed repository is not available. "
                "Run a scan first and wait for completion."
            ),
        )

    original_zip = artifact.get(
        "original_zip"
    )

    fixes = artifact.get(
        "fixes",
        [],
    )

    report = artifact.get(
        "report",
        {},
    )

    if not isinstance(
        original_zip,
        bytes,
    ):

        raise HTTPException(
            status_code=500,
            detail=(
                "Original repository artifact is unavailable."
            ),
        )

    try:

        fixed_zip = apply_fixes_to_zip(
            original_zip_bytes=original_zip,
            fixes=(
                fixes
                if isinstance(
                    fixes,
                    list,
                )
                else []
            ),
            report_result=(
                report
                if isinstance(
                    report,
                    dict,
                )
                else {}
            ),
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Could not create fixed repository ZIP: "
                f"{exc}"
            ),
        )

    base_name = "repository"

    original_filename = (
        report.get("filename")
        if isinstance(
            report,
            dict,
        )
        else None
    )

    if original_filename:

        base_name = Path(
            str(original_filename)
        ).stem

    download_name = (
        f"{base_name}_fixed.zip"
    )

    return StreamingResponse(
        io.BytesIO(fixed_zip),
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{download_name}"'
            )
        },
    )


# ============================================================
# MANIFEST
# ============================================================

@app.get("/scan/manifest/{scan_id}")
def get_scan_manifest(
    scan_id: str,
) -> dict[str, Any]:

    with SCAN_ARTIFACTS_LOCK:

        artifact = SCAN_ARTIFACTS.get(
            scan_id
        )

    if not artifact:

        raise HTTPException(
            status_code=404,
            detail="Scan artifact not found.",
        )

    report = artifact.get(
        "report",
        {},
    )

    fixes = artifact.get(
        "fixes",
        [],
    )

    if not isinstance(
        report,
        dict,
    ):
        report = {}

    successful_fixes: list[dict[str, Any]] = []

    if isinstance(
        fixes,
        list,
    ):

        for fix in fixes:

            if (
                isinstance(
                    fix,
                    dict,
                )
                and fix.get("success")
            ):

                successful_fixes.append(
                    {
                        "finding_id":
                            fix.get(
                                "finding_id"
                            ),

                        "original_path":
                            fix.get(
                                "original_path"
                            ),

                        "success":
                            True,

                        "fixed_code_length":
                            (
                                len(
                                    fix.get(
                                        "fixed_code",
                                        "",
                                    )
                                )
                                if isinstance(
                                    fix.get(
                                        "fixed_code"
                                    ),
                                    str,
                                )
                                else 0
                            ),
                    }
                )

    return {
        "application":
            "SentinelForge AI",

        "app_version":
            APP_VERSION,

        "scan_id":
            scan_id,

        "overall_risk":
            report.get(
                "overall_risk"
            ),

        "findings_count":
            report.get(
                "findings_count",
                0,
            ),

        "secret_count":
            report.get(
                "secret_count",
                0,
            ),

        "dependency_count":
            report.get(
                "dependency_count",
                0,
            ),

        "successful_fixes":
            successful_fixes,

        "validation":
            safe_json(
                report.get(
                    "validation",
                    {},
                )
            ),
    }


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

@app.post("/scan/upload")
async def legacy_scan_upload(
    file: UploadFile = File(...),
    role: str = Form("student"),
    email: str = Form(""),
) -> dict[str, Any]:

    normalized_role = normalize_role(
        role
    )

    if not email or not validate_email(
        email
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "A valid email address is required."
            ),
        )

    filename = (
        file.filename
        or "repository.zip"
    )

    if not filename.lower().endswith(
        ".zip"
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Please upload a ZIP repository."
            ),
        )

    zip_bytes = await file.read()

    if not zip_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded ZIP is empty.",
        )

    if len(zip_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=(
                "ZIP exceeds the upload limit."
            ),
        )

    scan_id = uuid.uuid4().hex

    with SCAN_PROGRESS_LOCK:

        SCAN_PROGRESS[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "progress": 0,
            "message":
                "Security analysis started.",
            "stages":
                build_initial_stages(),
            "data": None,
            "error": None,
        }

    run_scan_pipeline(
        scan_id,
        zip_bytes,
        filename,
        normalized_role,
        email.strip(),
    )

    with SCAN_PROGRESS_LOCK:

        result = SCAN_PROGRESS.get(
            scan_id
        )

    if not result:

        raise HTTPException(
            status_code=500,
            detail=(
                "Scan result was lost."
            ),
        )

    if result.get("status") == "error":

        raise HTTPException(
            status_code=500,
            detail=(
                result.get("error")
                or "Security analysis failed."
            ),
        )

    return result.get(
        "data"
    ) or {}


# ============================================================
# PHASE 5 COMPATIBILITY
# ============================================================

@app.post("/phase5")
async def phase5_compatibility(
    file: UploadFile = File(...),
) -> dict[str, Any]:

    filename = (
        file.filename
        or "repository.zip"
    )

    zip_bytes = await file.read()

    if not filename.lower().endswith(
        ".zip"
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Please upload a ZIP repository."
            ),
        )

    if not zip_bytes:
        raise HTTPException(
            status_code=400,
            detail="Uploaded ZIP is empty.",
        )

    if len(zip_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=(
                "ZIP exceeds the upload limit."
            ),
        )

    scan_id = uuid.uuid4().hex

    with SCAN_PROGRESS_LOCK:

        SCAN_PROGRESS[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "progress": 0,
            "message":
                "Compatibility scan started.",
            "stages":
                build_initial_stages(),
            "data": None,
            "error": None,
        }

    run_scan_pipeline(
        scan_id,
        zip_bytes,
        filename,
        "student",
        "compatibility@example.com",
    )

    with SCAN_PROGRESS_LOCK:

        result = SCAN_PROGRESS.get(
            scan_id
        )

    if not result:
        return {}

    if result.get("status") == "error":
        raise HTTPException(
            status_code=500,
            detail=(
                result.get("error")
                or "Compatibility scan failed."
            ),
        )

    return (
        result.get("data")
        or {}
    )


# ============================================================
# PHASE 4 COMPATIBILITY
# ============================================================

@app.post("/phase4")
async def phase4_compatibility(
    file: UploadFile = File(...),
) -> dict[str, Any]:

    return await phase5_compatibility(
        file
    )