import json

from app.services.groq_service import generate_ai_response


# ============================================================
# PHASE 4 - COMPACT AI SECURITY ANALYSIS
# ============================================================

MAX_FINDINGS_FOR_AI = 8
MAX_SOURCE_CONTEXT_CHARS = 600
MAX_MESSAGE_CHARS = 300
MAX_TEXT_CHARS = 350


def _compact_text(value, max_chars):
    if value is None:
        return ""

    text = str(value).strip()

    if len(text) > max_chars:
        return text[:max_chars] + "...[truncated]"

    return text


def _compact_finding(finding, assessment):
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

    vulnerability_type = (
        assessment.get("vulnerability_type")
        or metadata.get("vulnerability_class")
        or "Security Vulnerability"
    )

    severity = (
        assessment.get("severity")
        or extra.get("severity")
        or "UNKNOWN"
    )

    cwe = (
        assessment.get("cwe")
        or metadata.get("cwe")
        or ""
    )

    if isinstance(cwe, list):
        cwe = ", ".join(
            str(item)
            for item in cwe[:3]
        )

    return {
        "rule": _compact_text(
            finding.get("check_id", ""),
            120,
        ),
        "type": _compact_text(
            vulnerability_type,
            120,
        ),
        "severity": _compact_text(
            severity,
            30,
        ),
        "cwe": _compact_text(
            cwe,
            80,
        ),
        "file": _compact_text(
            finding.get("path", ""),
            180,
        ),
        "line": start.get(
            "line",
            finding.get("line", ""),
        ),
        "message": _compact_text(
            extra.get("message", ""),
            MAX_MESSAGE_CHARS,
        ),
        "risk": _compact_text(
            assessment.get("risk_score", ""),
            30,
        ),
        "impact": _compact_text(
            assessment.get("impact", ""),
            MAX_TEXT_CHARS,
        ),
        "fix": _compact_text(
            assessment.get("recommendation", ""),
            MAX_TEXT_CHARS,
        ),
        "source": _compact_text(
            finding.get("source_code", ""),
            MAX_SOURCE_CONTEXT_CHARS,
        ),
    }


def analyze_security_findings(
    findings: list,
    role="developer",
    risk_assessments=None,
    overall_risk=None,
) -> str:

    if not findings:
        return (
            "No security vulnerabilities were detected."
        )

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

    normalized_role = str(
        role or "developer"
    ).strip().lower()

    if normalized_role not in {
        "student",
        "developer",
    }:
        normalized_role = "developer"

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

            possible_assessment = (
                risk_assessments[index]
            )

            if isinstance(
                possible_assessment,
                dict,
            ):
                assessment = (
                    possible_assessment
                )

        compact_findings.append(
            _compact_finding(
                finding,
                assessment,
            )
        )

    findings_json = json.dumps(
        compact_findings,
        ensure_ascii=False,
        separators=(",", ":"),
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
    # STUDENT
    # ========================================================

    if normalized_role == "student":

        prompt = f"""
You are SentinelForge AI.

Explain these security findings for a student.

Risk score: {overall_score}
Risk level: {overall_level}

Findings:
{findings_json}

For each important finding explain:
- what it is
- where it is
- why it happened
- possible attack
- impact
- prevention

End with:
- overall security condition
- most important fixes

Use simple language.

Do not claim the vulnerabilities are fixed.
Do not claim verification.
Do not claim a second scan.
"""

    # ========================================================
    # DEVELOPER
    # ========================================================

    else:

        prompt = f"""
You are SentinelForge AI, a senior security engineer.

Analyze these repository security findings.

Risk score: {overall_score}
Risk level: {overall_level}

Findings:
{findings_json}

For each important finding explain:
- vulnerability
- CWE
- severity
- file and line
- Semgrep rule/message
- root cause
- attack path
- impact
- remediation

End with:
- overall assessment
- highest priority fixes

Do not claim the vulnerabilities are fixed.
Do not claim verification.
Do not claim a second scan.
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

    return analyze_security_findings(
        findings=findings,
        role="developer",
    )