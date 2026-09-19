"""
SentinelForge AI - Report Utilities

Helper functions used to prepare structured security-report data
for the dashboard, PDF generation, email reports, and Auto-Fix display.

This module does not perform scanning, risk calculation, ML inference,
AI remediation, or validation. It only prepares existing results
for presentation.
"""

from __future__ import annotations

from typing import Any


def _safe_dict(value: Any) -> dict:
    """Return a dictionary or an empty dictionary."""
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> list:
    """Return a list or an empty list."""
    return value if isinstance(value, list) else []


def _first_value(data: dict, keys: list[str], default: Any = "") -> Any:
    """Return the first non-empty value from a dictionary."""
    for key in keys:
        value = data.get(key)

        if value is not None and value != "":
            return value

    return default


def get_finding_id(finding: dict, index: int) -> str:
    """
    Return the stable finding ID.

    Preferred source:
        finding_id

    Backward-compatible sources:
        id
        findingId

    Final fallback:
        F001, F002, ...
    """

    finding = _safe_dict(finding)

    finding_id = _first_value(
        finding,
        ["finding_id", "id", "findingId"],
        "",
    )

    if finding_id:
        return str(finding_id)

    return f"F{index:03d}"


def extract_ml_results(finding: dict) -> dict:
    """
    Extract all available ML intelligence from a finding.

    Supports both:
        finding["ml_results"]

    and direct ML fields.
    """

    finding = _safe_dict(finding)

    nested = _safe_dict(
        finding.get("ml_results")
    )

    triage = _safe_dict(
        _first_value(
            nested,
            ["ml_triage"],
            finding.get("ml_triage", {}),
        )
    )

    classification = _safe_dict(
        _first_value(
            nested,
            ["ml_classification"],
            finding.get("ml_classification", {}),
        )
    )

    severity = _safe_dict(
        _first_value(
            nested,
            ["ml_severity"],
            finding.get("ml_severity", {}),
        )
    )

    priority = _safe_dict(
        _first_value(
            nested,
            ["ml_priority"],
            finding.get("ml_priority", {}),
        )
    )

    code_context = _safe_dict(
        _first_value(
            nested,
            ["ml_code_context"],
            finding.get("ml_code_context", {}),
        )
    )

    fix_recommendation = _safe_dict(
        _first_value(
            nested,
            ["ml_fix_recommendation"],
            finding.get("ml_fix_recommendation", {}),
        )
    )

    return {
        "triage": triage,
        "classification": classification,
        "severity": severity,
        "priority": priority,
        "code_context": code_context,
        "fix_recommendation": fix_recommendation,
    }


def extract_ml_summary(finding: dict) -> dict:
    """
    Convert raw ML agent output into a simple report-friendly structure.
    """

    ml = extract_ml_results(finding)

    triage = ml["triage"]
    classification = ml["classification"]
    severity = ml["severity"]
    priority = ml["priority"]
    context = ml["code_context"]
    recommendation = ml["fix_recommendation"]

    return {
        "triage_prediction": _first_value(
            triage,
            ["prediction", "classification"],
            "Unknown",
        ),
        "triage_probability": _first_value(
            triage,
            ["vulnerability_probability"],
            "",
        ),
        "classification": _first_value(
            classification,
            ["predicted_type", "prediction"],
            "Unknown",
        ),
        "predicted_severity": _first_value(
            severity,
            ["predicted_severity", "prediction"],
            "Unknown",
        ),
        "severity_confidence": _first_value(
            severity,
            ["confidence"],
            "",
        ),
        "priority": _first_value(
            priority,
            ["predicted_priority", "prediction"],
            "Unknown",
        ),
        "priority_confidence": _first_value(
            priority,
            ["confidence"],
            "",
        ),
        "code_context": _first_value(
            context,
            ["predicted_context", "context"],
            "Unknown",
        ),
        "fix_recommendation": _first_value(
            recommendation,
            [
                "recommended_fix",
                "ml_predicted_fix",
                "prediction",
            ],
            "",
        ),
        "fix_confidence": _first_value(
            recommendation,
            ["confidence"],
            "",
        ),
    }


def build_finding_report(
    finding: dict,
    risk_assessment: dict | None = None,
    index: int = 1,
) -> dict:
    """
    Build one complete report record for a vulnerability finding.

    This does not change the original finding.
    """

    finding = _safe_dict(finding)
    risk_assessment = _safe_dict(risk_assessment)

    finding_id = get_finding_id(
        finding,
        index,
    )

    start = _safe_dict(
        finding.get("start")
    )

    extra = _safe_dict(
        finding.get("extra")
    )

    line = _first_value(
        start,
        ["line"],
        _first_value(
            finding,
            ["line"],
            "Unknown",
        ),
    )

    path = _first_value(
        finding,
        ["path", "file"],
        "Unknown",
    )

    check_id = _first_value(
        finding,
        ["check_id", "rule_id", "rule"],
        "Unknown",
    )

    message = _first_value(
        finding,
        ["message"],
        _first_value(
            extra,
            ["message"],
            "Security issue detected.",
        ),
    )

    vulnerability_type = _first_value(
        finding,
        [
            "vulnerability_type",
            "type",
            "classification",
        ],
        _first_value(
            risk_assessment,
            ["vulnerability_type"],
            _first_value(
                extra,
                [
                    "vulnerability_class",
                    "type",
                ],
                "Security vulnerability",
            ),
        ),
    )

    severity = _first_value(
        risk_assessment,
        ["severity"],
        _first_value(
            finding,
            ["severity"],
            _first_value(
                extra,
                ["severity"],
                "Unknown",
            ),
        ),
    )

    cwe = _first_value(
        risk_assessment,
        ["cwe"],
        _first_value(
            finding,
            ["cwe"],
            "",
        ),
    )

    owasp = _first_value(
        risk_assessment,
        ["owasp", "owasp_category"],
        _first_value(
            finding,
            ["owasp", "owasp_category"],
            "",
        ),
    )

    risk_score = _first_value(
        risk_assessment,
        ["risk_score", "score"],
        "",
    )

    risk_level = _first_value(
        risk_assessment,
        ["risk_level", "level"],
        "",
    )

    impact = _first_value(
        risk_assessment,
        ["impact"],
        "",
    )

    exploitability = _first_value(
        risk_assessment,
        ["exploitability"],
        "",
    )

    recommendation = _first_value(
        risk_assessment,
        ["recommendation", "remediation"],
        _first_value(
            finding,
            ["recommendation", "remediation"],
            "",
        ),
    )

    source_code = _first_value(
        finding,
        ["source_code", "code", "source"],
        "",
    )

    fixed_code = _first_value(
        finding,
        [
            "fixed_code",
            "ai_fixed_code",
            "fixed_source_code",
        ],
        "",
    )

    validation = _safe_dict(
        _first_value(
            finding,
            ["validation", "validation_result"],
            {},
        )
    )

    fix_status = _first_value(
        finding,
        [
            "ai_fix_status",
            "fix_status",
        ],
        "",
    )

    if not fix_status:
        if fixed_code:
            fix_status = "Generated"
        else:
            fix_status = "Not generated"

    validation_status = _first_value(
        validation,
        [
            "status",
            "validation_status",
            "result",
        ],
        _first_value(
            finding,
            [
                "validation_status",
            ],
            "Not validated",
        ),
    )

    ml_summary = extract_ml_summary(
        finding
    )

    return {
        "finding_id": finding_id,
        "index": index,
        "check_id": str(check_id),
        "vulnerability_type": str(
            vulnerability_type
        ),
        "message": str(message),
        "path": str(path),
        "line": line,
        "severity": str(severity),
        "cwe": str(cwe),
        "owasp": str(owasp),
        "risk_score": risk_score,
        "risk_level": str(risk_level),
        "impact": str(impact),
        "exploitability": str(
            exploitability
        ),
        "recommendation": str(
            recommendation
        ),
        "source_code": str(
            source_code
        ),
        "fixed_code": str(
            fixed_code
        ),
        "ai_fix_status": str(
            fix_status
        ),
        "validation_status": str(
            validation_status
        ),
        "ml": ml_summary,
    }


def build_duplicate_mapping(
    duplicate_results: list,
) -> list[dict]:
    """
    Normalize duplicate-similarity results.

    Expected mapping:

        F001 <-> F002

    The original similarity model output is preserved.
    """

    duplicate_results = _safe_list(
        duplicate_results
    )

    mappings = []

    for result in duplicate_results:

        if not isinstance(
            result,
            dict,
        ):
            continue

        index_1 = result.get(
            "finding_1_index"
        )

        index_2 = result.get(
            "finding_2_index"
        )

        finding_1_id = result.get(
            "finding_1_id"
        )

        finding_2_id = result.get(
            "finding_2_id"
        )

        if not finding_1_id and index_1 is not None:
            finding_1_id = (
                f"F{int(index_1):03d}"
            )

        if not finding_2_id and index_2 is not None:
            finding_2_id = (
                f"F{int(index_2):03d}"
            )

        prediction = result.get(
            "prediction",
            "",
        )

        classification = result.get(
            "classification",
            "",
        )

        probability = result.get(
            "similarity_probability",
            "",
        )

        confidence = result.get(
            "confidence",
            "",
        )

        is_duplicate = (
            str(classification).strip().lower()
            == "similar"
        )

        mappings.append(
            {
                "finding_1_id": finding_1_id or "",
                "finding_2_id": finding_2_id or "",
                "classification": (
                    classification
                    or (
                        "Similar"
                        if is_duplicate
                        else "Not Similar"
                    )
                ),
                "duplicate": is_duplicate,
                "similarity_probability": (
                    probability
                ),
                "confidence": confidence,
                "prediction": prediction,
            }
        )

    return mappings


def summarize_fixes(
    fixes: list,
) -> dict:
    """
    Create a report-friendly Auto-Fix summary.
    """

    fixes = _safe_list(fixes)

    total = 0
    successful = 0
    failed = 0
    validation_count = 0

    details = []

    for index, fix in enumerate(
        fixes,
        start=1,
    ):

        if not isinstance(
            fix,
            dict,
        ):
            continue

        total += 1

        success = bool(
            fix.get(
                "success",
                False,
            )
        )

        if success:
            successful += 1
        else:
            failed += 1

        validation = _safe_dict(
            fix.get("validation")
        )

        if validation:
            validation_count += 1

        finding_id = _first_value(
            fix,
            [
                "finding_id",
                "findingId",
            ],
            f"F{index:03d}",
        )

        details.append(
            {
                "finding_id": str(
                    finding_id
                ),
                "success": success,
                "status": (
                    "Generated"
                    if success
                    else "Failed"
                ),
                "path": _first_value(
                    fix,
                    ["path", "file"],
                    "",
                ),
                "message": _first_value(
                    fix,
                    ["message"],
                    "",
                ),
                "validation": validation,
                "original_code": _first_value(
                    fix,
                    [
                        "original_code",
                        "source_code",
                    ],
                    "",
                ),
                "fixed_code": _first_value(
                    fix,
                    [
                        "fixed_code",
                        "ai_fixed_code",
                        "fixed_source_code",
                    ],
                    "",
                ),
            }
        )

    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "validation_results": validation_count,
        "details": details,
    }


def build_security_report_data(
    filename: str,
    findings: list,
    risk_assessments: list,
    overall_risk: dict,
    fixes: list | None = None,
    secrets: dict | list | None = None,
    dependencies: dict | list | None = None,
    duplicate_results: list | None = None,
) -> dict:
    """
    Build the complete structured data used by future dashboard/PDF/report
    presentation layers.

    This function only organizes existing data.
    """

    findings = _safe_list(findings)
    risk_assessments = _safe_list(
        risk_assessments
    )
    fixes = _safe_list(fixes)
    duplicate_results = _safe_list(
        duplicate_results
    )

    overall_risk = _safe_dict(
        overall_risk
    )

    report_findings = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        assessment = {}

        if index - 1 < len(
            risk_assessments
        ):
            candidate = risk_assessments[
                index - 1
            ]

            if isinstance(
                candidate,
                dict,
            ):
                assessment = candidate

        report_findings.append(
            build_finding_report(
                finding=finding,
                risk_assessment=assessment,
                index=index,
            )
        )

    severity_counts = _safe_dict(
        overall_risk.get(
            "severity_counts"
        )
    )

    secret_count = 0

    if isinstance(
        secrets,
        dict,
    ):
        secret_count = _first_value(
            secrets,
            [
                "count",
                "total",
                "secret_count",
            ],
            len(
                _safe_list(
                    secrets.get(
                        "findings"
                    )
                )
            ),
        )

    elif isinstance(
        secrets,
        list,
    ):
        secret_count = len(secrets)

    dependency_count = 0

    if isinstance(
        dependencies,
        dict,
    ):
        dependency_count = _first_value(
            dependencies,
            [
                "vulnerability_count",
                "count",
                "total",
            ],
            len(
                _safe_list(
                    dependencies.get(
                        "vulnerabilities"
                    )
                )
            ),
        )

    elif isinstance(
        dependencies,
        list,
    ):
        dependency_count = len(
            dependencies
        )

    return {
        "repository": str(
            filename or ""
        ),
        "summary": {
            "finding_count": len(
                report_findings
            ),
            "critical": severity_counts.get(
                "CRITICAL",
                0,
            ),
            "high": severity_counts.get(
                "HIGH",
                0,
            ),
            "medium": severity_counts.get(
                "MEDIUM",
                0,
            ),
            "low": severity_counts.get(
                "LOW",
                0,
            ),
            "info": severity_counts.get(
                "INFO",
                0,
            ),
            "secret_count": secret_count,
            "dependency_vulnerability_count": (
                dependency_count
            ),
            "overall_risk_score": _first_value(
                overall_risk,
                [
                    "score",
                    "overall_score",
                ],
                0,
            ),
            "overall_risk_level": _first_value(
                overall_risk,
                [
                    "risk_level",
                    "level",
                ],
                "Secure",
            ),
        },
        "findings": report_findings,
        "auto_fix": summarize_fixes(
            fixes
        ),
        "duplicate_similarity": (
            build_duplicate_mapping(
                duplicate_results
            )
        ),
        "secrets": secrets
        if secrets is not None
        else {},
        "dependencies": (
            dependencies
            if dependencies is not None
            else {}
        ),
    }


def build_code_diff(
    original_code: str,
    fixed_code: str,
) -> str:
    """
    Build a simple unified diff for display.

    The function does not modify either source.
    """

    import difflib

    original_lines = str(
        original_code or ""
    ).splitlines()

    fixed_lines = str(
        fixed_code or ""
    ).splitlines()

    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile="original",
        tofile="ai-fixed",
        lineterm="",
    )

    return "\n".join(diff)