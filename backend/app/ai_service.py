import json

from app.services.groq_service import generate_ai_response


# ============================================================
# PHASE 4 - AI SECURITY ANALYSIS
# ============================================================

MAX_FINDINGS_FOR_AI = 20
MAX_SOURCE_CONTEXT_CHARS = 1800
MAX_MESSAGE_CHARS = 700


def _clean_text(value, max_chars):
    """
    Convert a value to a compact string and limit its size.
    """

    if value is None:
        return ""

    text = str(value).strip()

    if len(text) > max_chars:
        return text[:max_chars] + "\n...[truncated]"

    return text


def _compact_finding(finding, assessment=None):
    """
    Keep only the information required by the AI.

    Large scanner fields such as complete source context,
    raw metadata and unrelated fields are intentionally
    removed to keep the Groq request small.
    """

    if not isinstance(finding, dict):
        finding = {}

    if not isinstance(assessment, dict):
        assessment = {}

    extra = finding.get("extra", {})

    if not isinstance(extra, dict):
        extra = {}

    metadata = extra.get("metadata", {})

    if not isinstance(metadata, dict):
        metadata = {}

    start = finding.get("start", {})

    if not isinstance(start, dict):
        start = {}

    severity = (
        assessment.get("severity")
        or extra.get("severity")
        or "UNKNOWN"
    )

    vulnerability_type = (
        assessment.get("vulnerability_type")
        or metadata.get("vulnerability_class")
        or "Security Vulnerability"
    )

    cwe = (
        assessment.get("cwe")
        or metadata.get("cwe")
        or ""
    )

    if isinstance(cwe, list):
        cwe = ", ".join(
            str(item)
            for item in cwe[:5]
        )

    return {
        "check_id": _clean_text(
            finding.get(
                "check_id",
                "unknown",
            ),
            250,
        ),
        "vulnerability_type": _clean_text(
            vulnerability_type,
            250,
        ),
        "severity": _clean_text(
            severity,
            50,
        ),
        "cwe": _clean_text(
            cwe,
            150,
        ),
        "path": _clean_text(
            finding.get(
                "path",
                "unknown",
            ),
            400,
        ),
        "line": start.get(
            "line",
            finding.get(
                "line",
                "unknown",
            ),
        ),
        "message": _clean_text(
            extra.get(
                "message",
                "Security issue detected.",
            ),
            MAX_MESSAGE_CHARS,
        ),
        "risk_score": assessment.get(
            "risk_score",
            "N/A",
        ),
        "risk_level": assessment.get(
            "risk_level",
            "N/A",
        ),
        "impact": _clean_text(
            assessment.get(
                "impact",
                "",
            ),
            500,
        ),
        "exploitability": _clean_text(
            assessment.get(
                "exploitability",
                "",
            ),
            500,
        ),
        "recommendation": _clean_text(
            assessment.get(
                "recommendation",
                "",
            ),
            700,
        ),
        "source_code": _clean_text(
            finding.get(
                "source_code",
                "",
            ),
            MAX_SOURCE_CONTEXT_CHARS,
        ),
    }


def analyze_security_findings(
    findings: list,
    role="developer",
    risk_assessments=None,
    overall_risk=None,
) -> str:
    """
    Generate compact but useful AI security analysis.

    The prompt is intentionally limited so that it stays
    within Groq free-tier token limits.
    """

    if not findings:
        return (
            "No security vulnerabilities were detected "
            "during the security scanning stage."
        )

    normalized_role = str(
        role or "developer"
    ).strip().lower()

    if normalized_role not in {
        "student",
        "developer",
    }:
        normalized_role = "developer"

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

    # --------------------------------------------------------
    # LIMIT FINDINGS
    # --------------------------------------------------------

    selected_findings = findings[
        :MAX_FINDINGS_FOR_AI
    ]

    compact_findings = []

    for index, finding in enumerate(
        selected_findings
    ):
        assessment = {}

        if index < len(
            risk_assessments
        ):
            candidate = risk_assessments[
                index
            ]

            if isinstance(
                candidate,
                dict,
            ):
                assessment = candidate

        compact_findings.append(
            _compact_finding(
                finding,
                assessment,
            )
        )

    findings_json = json.dumps(
        compact_findings,
        ensure_ascii=False,
        separators=(
            ",",
            ":",
        ),
    )

    overall_score = overall_risk.get(
        "score",
        overall_risk.get(
            "overall_score",
            "N/A",
        ),
    )

    overall_level = overall_risk.get(
        "risk_level",
        overall_risk.get(
            "level",
            "N/A",
        ),
    )

    # ========================================================
    # STUDENT PROMPT
    # ========================================================

    if normalized_role == "student":

        prompt = f"""
You are SentinelForge AI, an educational cybersecurity assistant.

Analyze the following security findings.

Overall risk score: {overall_score}
Overall risk level: {overall_level}

Findings:
{findings_json}

Explain the result in simple language.

For each important vulnerability explain:
1. What the vulnerability is.
2. Where it occurs.
3. Why it happened.
4. How an attacker could potentially abuse it.
5. What could happen if it remains unfixed.
6. How developers can prevent or fix it.
7. What SentinelForge AI detected and prepared.

Then provide:
- Overall security condition.
- Most important issues to fix first.
- Practical learning recommendations.

Do NOT claim that vulnerabilities were fixed.
Do NOT claim that fixes were verified.
Do NOT claim that a second security scan occurred.
"""

    # ========================================================
    # DEVELOPER PROMPT
    # ========================================================

    else:

        prompt = f"""
You are SentinelForge AI, a senior application security engineer.

Analyze the following repository security findings.

Overall risk score: {overall_score}
Overall risk level: {overall_level}

Findings:
{findings_json}

Provide a technical security assessment.

For each significant finding include:
- Vulnerability type
- CWE
- Severity
- Risk score
- File/path
- Line
- Semgrep rule
- Semgrep message
- Root cause
- Potential attack path
- Impact
- Exploitability
- Recommended remediation
- Relevant source context

Then provide:
- Overall risk assessment.
- Highest-priority remediation items.
- Practical developer recommendations.

Keep the answer focused and technically useful.

Do NOT claim that vulnerabilities were fixed.
Do NOT claim that fixes were verified.
Do NOT claim that a second security scan occurred.
"""

    # ========================================================
    # GROQ
    # ========================================================

    response = generate_ai_response(
        prompt
    )

    if not response:
        raise ValueError(
            "Groq returned an empty AI analysis."
        )

    response = str(
        response
    ).strip()

    if not response:
        raise ValueError(
            "Groq returned an empty AI analysis."
        )

    return response


# ============================================================
# LEGACY COMPATIBILITY
# ============================================================

async def analyze_with_groq(
    findings: list,
) -> str:
    """
    Backward-compatible wrapper.
    """

    return analyze_security_findings(
        findings=findings,
        role="developer",
    )