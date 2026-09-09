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


def compact_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Keep only security-relevant information from a finding.

    Large scanner fields are intentionally ignored.
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
        or "Security Vulnerability"
    )


    cwe = metadata.get(
        "cwe",
        "",
    )


    if isinstance(
        cwe,
        list,
    ):
        cwe = ", ".join(
            str(item)
            for item in cwe[:5]
        )


    return {
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
                "UNKNOWN",
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
                "",
            ),
            650,
        ),
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

    This allows several security findings in one file to be
    fixed with ONE Groq request.
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

        finding_lines.append(
            f"""
Finding {index}:
Rule: {finding.get("rule", "unknown")}
Type: {finding.get("type", "unknown")}
Severity: {finding.get("severity", "unknown")}
CWE: {finding.get("cwe", "not specified")}
Line: {finding.get("line", "unknown")}
Message: {finding.get("message", "Security issue detected.")}
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

IMPORTANT:
Several Semgrep rules can report the same underlying
security issue. Treat all supplied findings as one combined
security remediation task.

Your task is to return the COMPLETE corrected source file.

Requirements:

1. Fix all listed security issues in this source file.
2. Make the smallest practical security changes.
3. Preserve existing application functionality.
4. Preserve unrelated code.
5. Do not remove working functionality.
6. Do not introduce unnecessary dependencies.
7. Prefer libraries already used by the project.
8. Return the COMPLETE source file.
9. Do not return a snippet.
10. Do not return a diff.
11. Do not return an explanation.
12. Do not return Markdown code fences.
13. Do not return a FIXED_CODE label.
14. Return ONLY the corrected source code.
15. Do not claim that the code was verified.
16. Do not claim that another security scan was performed.

Examples:

SQL Injection:
Use parameterized queries or another safe database
operation instead of string concatenation.

Debug Mode:
Do not expose production debug mode.

Other vulnerabilities:
Apply the appropriate secure coding remediation based on
the actual source code and the listed findings.

If the security issue cannot be safely fixed with the
available source context, return the original source code
unchanged.

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