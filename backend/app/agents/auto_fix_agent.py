from __future__ import annotations

from typing import Any

from app.services.groq_service import generate_ai_response


# ============================================================
# LIMITS
# ============================================================

# Keep the complete source reasonably small so that the
# Auto-Fix request stays within the Groq token limit.
MAX_SOURCE_CHARS = 12000

# Keep individual finding information compact.
MAX_TEXT_CHARS = 500


# ============================================================
# HELPERS
# ============================================================

def clean_text(
    value: Any,
    max_chars: int = MAX_TEXT_CHARS,
) -> str:
    """
    Convert a value to compact text.
    """

    if value is None:
        return ""

    text = str(value).strip()

    if len(text) > max_chars:
        return (
            text[:max_chars]
            + "...[truncated]"
        )

    return text


def _get_first_value(
    data: dict[str, Any],
    keys: list[str],
    default: Any = "",
) -> Any:
    """
    Return the first non-empty value from a dictionary.

    This keeps the Auto-Fix Agent compatible with slightly
    different ML result field names.
    """

    if not isinstance(
        data,
        dict,
    ):
        return default

    for key in keys:

        value = data.get(key)

        if value is None:
            continue

        if isinstance(
            value,
            str,
        ):

            if not value.strip():
                continue

        return value

    return default


def _extract_ml_result(
    finding: dict[str, Any],
    result_name: str,
    aliases: list[str],
) -> dict[str, Any]:
    """
    Extract one ML result from a finding.

    The main pipeline will attach the ML outputs to findings.
    This helper supports both the planned explicit field names
    and a nested 'ml_results' structure.
    """

    if not isinstance(
        finding,
        dict,
    ):
        return {}

    # --------------------------------------------------------
    # Direct field
    # --------------------------------------------------------

    direct = finding.get(
        result_name
    )

    if isinstance(
        direct,
        dict,
    ):
        return direct

    # --------------------------------------------------------
    # Nested ML result structure
    # --------------------------------------------------------

    ml_results = finding.get(
        "ml_results",
        {},
    )

    if isinstance(
        ml_results,
        dict,
    ):

        nested = ml_results.get(
            result_name
        )

        if isinstance(
            nested,
            dict,
        ):
            return nested

        for alias in aliases:

            nested = ml_results.get(
                alias
            )

            if isinstance(
                nested,
                dict,
            ):
                return nested

    # --------------------------------------------------------
    # Alternate direct aliases
    # --------------------------------------------------------

    for alias in aliases:

        value = finding.get(
            alias
        )

        if isinstance(
            value,
            dict,
        ):
            return value

    return {}


def _compact_ml_intelligence(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract the useful ML intelligence associated with a finding.

    ML is supplementary intelligence. It does not replace
    Semgrep detection or the deterministic Risk Engine.
    """

    if not isinstance(
        finding,
        dict,
    ):
        return {}

    # --------------------------------------------------------
    # Vulnerability classification
    # --------------------------------------------------------

    classification = _extract_ml_result(
        finding,
        "ml_classification",
        [
            "classification",
            "classification_result",
        ],
    )

    classification_value = _get_first_value(
        classification,
        [
            "prediction",
            "predicted_class",
            "classification",
            "vulnerability_type",
            "label",
        ],
    )

    classification_confidence = _get_first_value(
        classification,
        [
            "confidence",
            "probability",
            "vulnerability_probability",
        ],
    )

    # --------------------------------------------------------
    # Severity prediction
    # --------------------------------------------------------

    severity = _extract_ml_result(
        finding,
        "ml_severity",
        [
            "severity",
            "severity_prediction",
            "severity_result",
        ],
    )

    severity_value = _get_first_value(
        severity,
        [
            "prediction",
            "predicted_severity",
            "severity",
            "label",
        ],
    )

    severity_confidence = _get_first_value(
        severity,
        [
            "confidence",
            "probability",
        ],
    )

    # --------------------------------------------------------
    # Priority prediction
    # --------------------------------------------------------

    priority = _extract_ml_result(
        finding,
        "ml_priority",
        [
            "priority",
            "priority_prediction",
            "priority_result",
        ],
    )

    priority_value = _get_first_value(
        priority,
        [
            "prediction",
            "predicted_priority",
            "priority",
            "label",
        ],
    )

    priority_confidence = _get_first_value(
        priority,
        [
            "confidence",
            "probability",
        ],
    )

    # --------------------------------------------------------
    # Code context
    # --------------------------------------------------------

    context = _extract_ml_result(
        finding,
        "ml_code_context",
        [
            "code_context",
            "context",
            "code_context_result",
        ],
    )

    context_value = _get_first_value(
        context,
        [
            "prediction",
            "predicted_context",
            "context",
            "code_context",
            "label",
        ],
    )

    context_confidence = _get_first_value(
        context,
        [
            "confidence",
            "probability",
        ],
    )

    # --------------------------------------------------------
    # Fix recommendation
    # --------------------------------------------------------

    recommendation = _extract_ml_result(
        finding,
        "ml_fix_recommendation",
        [
            "fix_recommendation",
            "recommendation",
            "fix_recommendation_result",
        ],
    )

    recommendation_value = _get_first_value(
        recommendation,
        [
            "recommendation",
            "prediction",
            "predicted_recommendation",
            "fix",
            "label",
        ],
    )

    recommendation_confidence = _get_first_value(
        recommendation,
        [
            "confidence",
            "probability",
        ],
    )

    # --------------------------------------------------------
    # Triage
    # --------------------------------------------------------

    triage = _extract_ml_result(
        finding,
        "ml_triage",
        [
            "triage",
            "triage_result",
        ],
    )

    triage_value = _get_first_value(
        triage,
        [
            "prediction",
            "classification",
            "triage",
            "label",
        ],
    )

    triage_probability = _get_first_value(
        triage,
        [
            "probability",
            "vulnerability_probability",
        ],
    )

    triage_confidence = _get_first_value(
        triage,
        [
            "confidence",
        ],
    )

    return {
        "triage": {
            "prediction": clean_text(
                triage_value,
                120,
            ),
            "probability": clean_text(
                triage_probability,
                60,
            ),
            "confidence": clean_text(
                triage_confidence,
                60,
            ),
        },

        "classification": {
            "prediction": clean_text(
                classification_value,
                150,
            ),
            "confidence": clean_text(
                classification_confidence,
                60,
            ),
        },

        "severity_prediction": {
            "prediction": clean_text(
                severity_value,
                60,
            ),
            "confidence": clean_text(
                severity_confidence,
                60,
            ),
        },

        "priority": {
            "prediction": clean_text(
                priority_value,
                60,
            ),
            "confidence": clean_text(
                priority_confidence,
                60,
            ),
        },

        "code_context": {
            "prediction": clean_text(
                context_value,
                120,
            ),
            "confidence": clean_text(
                context_confidence,
                60,
            ),
        },

        "fix_recommendation": {
            "recommendation": clean_text(
                recommendation_value,
                400,
            ),
            "confidence": clean_text(
                recommendation_confidence,
                60,
            ),
        },
    }


def compact_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Keep only security-relevant information from a finding.

    Large scanner fields are intentionally ignored.

    ML intelligence is included when it has already been
    attached to the finding by the main pipeline.
    """

    if not isinstance(
        finding,
        dict,
    ):
        return {}

    extra = finding.get(
        "extra",
        {},
    )

    if not isinstance(
        extra,
        dict,
    ):
        extra = {}

    metadata = extra.get(
        "metadata",
        {},
    )

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {}

    start = finding.get(
        "start",
        {},
    )

    if not isinstance(
        start,
        dict,
    ):
        start = {}

    vulnerability_type = (
        metadata.get(
            "vulnerability_class"
        )
        or finding.get(
            "vulnerability_type"
        )
        or "Security Vulnerability"
    )

    cwe = metadata.get(
        "cwe",
        finding.get(
            "cwe",
            "",
        ),
    )

    if isinstance(
        cwe,
        list,
    ):
        cwe = ", ".join(
            str(item)
            for item in cwe[:5]
        )

    ml_intelligence = _compact_ml_intelligence(
        finding
    )

    # --------------------------------------------------------
    # Stable finding ID
    # --------------------------------------------------------

    finding_id = (
        finding.get(
            "finding_id"
        )
        or finding.get(
            "findingId"
        )
        or finding.get(
            "id"
        )
        or ""
    )

    # --------------------------------------------------------
    # Official risk information
    # --------------------------------------------------------

    risk_score = (
        finding.get(
            "risk_score"
        )
        or finding.get(
            "risk"
        )
        or ""
    )

    risk_level = (
        finding.get(
            "risk_level"
        )
        or ""
    )

    return {
        "finding_id": clean_text(
            finding_id,
            40,
        ),

        "rule": clean_text(
            finding.get(
                "check_id",
                "unknown",
            ),
            180,
        ),

        "type": clean_text(
            vulnerability_type,
            180,
        ),

        "severity": clean_text(
            extra.get(
                "severity",
                finding.get(
                    "severity",
                    "UNKNOWN",
                ),
            ),
            40,
        ),

        "cwe": clean_text(
            cwe,
            120,
        ),

        "line": start.get(
            "line",
            finding.get(
                "line",
                "unknown",
            ),
        ),

        "message": clean_text(
            extra.get(
                "message",
                finding.get(
                    "message",
                    "",
                ),
            ),
            650,
        ),

        "risk_score": clean_text(
            risk_score,
            60,
        ),

        "risk_level": clean_text(
            risk_level,
            60,
        ),

        "ml_intelligence": ml_intelligence,
    }


def clean_ai_response(
    response: str,
) -> str:
    """
    Remove accidental Markdown code fences or labels.
    """

    if not response:
        return ""

    text = str(
        response
    ).strip()

    lines = text.splitlines()

    if not lines:
        return ""

    # --------------------------------------------------------
    # Remove accidental opening code fence.
    # --------------------------------------------------------

    if lines[0].strip().startswith(
        "```"
    ):
        lines = lines[1:]

    # --------------------------------------------------------
    # Remove accidental closing code fence.
    # --------------------------------------------------------

    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]

    cleaned = "\n".join(
        lines
    ).strip()

    # --------------------------------------------------------
    # Remove accidental FIXED_CODE prefix.
    # --------------------------------------------------------

    if cleaned.startswith(
        "FIXED_CODE:"
    ):

        cleaned = cleaned[
            len("FIXED_CODE:"):
        ].strip()

    return cleaned


# ============================================================
# AUTO-FIX AGENT
# ============================================================

def generate_fix(
    vulnerability: dict[str, Any],
    source_code: str,
) -> str:
    """
    Generate one corrected source file.

    The vulnerability object may contain:

        related_findings

    which represents all Semgrep findings belonging to the
    same source file.

    ML intelligence can also be attached to each finding.
    The ML information is supplied to Groq as supporting
    security context.

    Semgrep remains the primary detection source.
    The deterministic Risk Engine remains the official risk
    source.
    """

    if not isinstance(
        vulnerability,
        dict,
    ):
        raise ValueError(
            "Invalid vulnerability data."
        )

    if not isinstance(
        source_code,
        str,
    ):
        raise ValueError(
            "Source code must be a string."
        )

    if not source_code.strip():
        raise ValueError(
            "Source code is empty."
        )

    # ========================================================
    # SOURCE SIZE
    # ========================================================

    if len(source_code) > MAX_SOURCE_CHARS:

        raise ValueError(
            "Source file is too large for the "
            "current Auto-Fix token limit."
        )

    # ========================================================
    # FILE INFORMATION
    # ========================================================

    file_path = clean_text(
        vulnerability.get(
            "path",
            "unknown",
        ),
        400,
    )

    # ========================================================
    # RELATED FINDINGS
    # ========================================================

    related_findings = vulnerability.get(
        "related_findings",
        [],
    )

    if not isinstance(
        related_findings,
        list,
    ):
        related_findings = []

    # If main.py sends no grouped findings,
    # fall back to the current finding.
    if not related_findings:

        related_findings = [
            vulnerability
        ]

    compact_findings = []

    for finding in related_findings:

        compact = compact_finding(
            finding
        )

        if compact:
            compact_findings.append(
                compact
            )

    # ========================================================
    # FINDING TEXT
    # ========================================================

    finding_lines = []

    for index, finding in enumerate(
        compact_findings,
        start=1,
    ):

        ml = finding.get(
            "ml_intelligence",
            {},
        )

        triage = ml.get(
            "triage",
            {},
        )

        classification = ml.get(
            "classification",
            {},
        )

        severity_prediction = ml.get(
            "severity_prediction",
            {},
        )

        priority = ml.get(
            "priority",
            {},
        )

        code_context = ml.get(
            "code_context",
            {},
        )

        fix_recommendation = ml.get(
            "fix_recommendation",
            {},
        )

        finding_lines.append(
            f"""
Finding {index}:
Finding ID: {finding.get("finding_id", "not assigned")}
Rule: {finding.get("rule", "unknown")}
Type: {finding.get("type", "unknown")}
Official Severity: {finding.get("severity", "unknown")}
Official Risk Level: {finding.get("risk_level", "not provided")}
Official Risk Score: {finding.get("risk_score", "not provided")}
CWE: {finding.get("cwe", "not specified")}
Line: {finding.get("line", "unknown")}
Message: {finding.get("message", "Security issue detected.")}

ML Security Intelligence:
- Triage Prediction: {triage.get("prediction", "not available")}
- Triage Probability: {triage.get("probability", "not available")}
- Triage Confidence: {triage.get("confidence", "not available")}
- ML Vulnerability Classification: {classification.get("prediction", "not available")}
- ML Classification Confidence: {classification.get("confidence", "not available")}
- ML Severity Prediction: {severity_prediction.get("prediction", "not available")}
- ML Severity Confidence: {severity_prediction.get("confidence", "not available")}
- ML Priority Prediction: {priority.get("prediction", "not available")}
- ML Priority Confidence: {priority.get("confidence", "not available")}
- ML Code Context: {code_context.get("prediction", "not available")}
- ML Code Context Confidence: {code_context.get("confidence", "not available")}
- ML Fix Recommendation: {fix_recommendation.get("recommendation", "not available")}
- ML Fix Recommendation Confidence: {fix_recommendation.get("confidence", "not available")}
"""
        )

    all_findings_text = "\n".join(
        finding_lines
    )

    # ========================================================
    # GROQ PROMPT
    # ========================================================

    prompt = f"""
You are the Auto-Fix Agent of a software repository
security analysis system.

You are fixing ALL security findings listed below that
belong to the SAME source file.

Source file:
{file_path}

Detected security findings:
{all_findings_text}

IMPORTANT SECURITY INFORMATION:

Semgrep is the primary security detection source.

The official risk level and risk score come from the
deterministic Risk Engine.

The ML results are supporting intelligence only. They help
you understand the vulnerability type, severity, priority,
code context, and possible remediation.

Do NOT treat an ML prediction as a replacement for the
actual Semgrep finding or official risk assessment.

IMPORTANT:
Several Semgrep rules can report the same underlying
security issue. Treat all supplied findings as one combined
security remediation task.

Your task is to return the COMPLETE corrected source file.

Requirements:

1. Fix all listed security issues in this source file.
2. Use the actual source code as the primary basis for the fix.
3. Use the Semgrep findings as the primary vulnerability evidence.
4. Use the ML results as supporting security context.
5. Respect the official risk level and severity information.
6. Use the ML fix recommendation when it is relevant and
   consistent with the actual vulnerability.
7. Make the smallest practical security changes.
8. Preserve existing application functionality.
9. Preserve unrelated code.
10. Do not remove working functionality.
11. Do not introduce unnecessary dependencies.
12. Prefer libraries already used by the project.
13. Return the COMPLETE source file.
14. Do not return a snippet.
15. Do not return a diff.
16. Do not return an explanation.
17. Do not return Markdown code fences.
18. Do not return a FIXED_CODE label.
19. Return ONLY the corrected source code.
20. Do not claim that the code was verified.
21. Do not claim that another security scan was performed.
22. Do not claim that the vulnerability is definitely resolved.
23. If the supplied ML information conflicts with the actual
    source code, prioritize the actual source code and
    Semgrep finding.
24. If the security issue cannot be safely fixed with the
    available source context, return the original source code
    unchanged.

Examples:

SQL Injection:
Use parameterized queries or another safe database
operation instead of string concatenation.

Debug Mode:
Do not expose production debug mode.

Other vulnerabilities:
Apply the appropriate secure coding remediation based on
the actual source code and the listed findings.

============================================================
ORIGINAL SOURCE CODE
============================================================

{source_code}

============================================================
FINAL RESPONSE
============================================================

Return ONLY the complete corrected source file.
"""

    # ========================================================
    # GROQ
    # ========================================================

    fixed_code = generate_ai_response(
        prompt
    )

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned an empty response."
        )

    fixed_code = clean_ai_response(
        fixed_code
    )

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned empty corrected code."
        )

    # ========================================================
    # INVALID RESPONSE CHECK
    # ========================================================

    invalid_responses = {
        "UNABLE_TO_FIX",
        "UNABLE TO FIX",
        "NOT_AVAILABLE",
        "NOT AVAILABLE",
    }

    if fixed_code.strip().upper() in (
        invalid_responses
    ):

        raise ValueError(
            "Auto-Fix Agent could not safely generate a fix."
        )

    return fixed_code