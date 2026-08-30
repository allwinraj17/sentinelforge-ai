# ============================================================
# AI SERVICE
# ============================================================

import json

from app.services.groq_service import (
    generate_ai_response,
)


# ============================================================
# ANALYZE SECURITY FINDINGS WITH GROQ
# ============================================================

async def analyze_with_groq(findings: list) -> str:
    """
    Analyze security findings using Groq.

    This function does not modify the uploaded repository.
    It only sends the security findings to the AI model
    and returns the generated analysis.
    """

    # --------------------------------------------------------
    # VALIDATE FINDINGS
    # --------------------------------------------------------

    if not findings:
        raise ValueError(
            "No security findings were provided."
        )

    # --------------------------------------------------------
    # PREPARE FINDINGS
    # --------------------------------------------------------

    findings_json = json.dumps(
        findings,
        indent=2,
        default=str,
    )

    # --------------------------------------------------------
    # CREATE SECURITY ANALYSIS PROMPT
    # --------------------------------------------------------

    prompt = f"""
You are the Security Analysis Agent of SentinelForge AI.

Analyze the following security vulnerabilities detected
in a software repository.

Your job is to provide a professional cybersecurity analysis.

SECURITY FINDINGS:
{findings_json}

For each vulnerability, explain:

1. Vulnerability name
2. Severity
3. Why the vulnerability exists
4. Security impact
5. Attack scenario
6. Recommended remediation
7. Secure coding recommendation

Then provide:

- Overall security assessment
- Most critical vulnerabilities
- Priority order for fixing vulnerabilities
- General security recommendations

Important rules:

- Do not modify any files.
- Do not claim that a vulnerability is fixed.
- Do not invent vulnerabilities that are not present.
- Base your analysis only on the provided findings.
- Use clear and professional language.
"""

    # --------------------------------------------------------
    # CALL GROQ
    # --------------------------------------------------------

    analysis = generate_ai_response(
        prompt
    )

    # --------------------------------------------------------
    # VALIDATE RESPONSE
    # --------------------------------------------------------

    if not analysis:
        raise RuntimeError(
            "Groq returned an empty security analysis."
        )

    return analysis.strip()