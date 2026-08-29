from app.services.groq_service import generate_ai_response


def generate_fix(
    vulnerability: dict,
    source_code: str,
) -> str:
    """
    Generate a secure code-fix suggestion.

    This function does NOT modify the repository.
    """

    check_id = vulnerability.get(
        "check_id",
        "unknown",
    )

    message = vulnerability.get(
        "extra",
        {},
    ).get(
        "message",
        "",
    )

    file_path = vulnerability.get(
        "path",
        "",
    )

    line = vulnerability.get(
        "start",
        {},
    ).get(
        "line",
        "",
    )

    prompt = f"""
You are the Auto-Fix Agent of SentinelForge AI.

Analyze the Semgrep vulnerability and propose a secure,
minimal fix.

RULES:
1. Do NOT modify the repository.
2. Do NOT invent libraries.
3. Do NOT rewrite unrelated code.
4. Preserve original functionality.
5. Make the smallest practical security fix.
6. Do not guess if context is insufficient.
7. Clearly show BEFORE and AFTER code.
8. This is only a suggested fix.
9. Never claim the fix was applied.

VULNERABILITY
=============

Rule ID:
{check_id}

Message:
{message}

File:
{file_path}

Detected line:
{line}

SOURCE CODE CONTEXT
===================

{source_code}

RETURN EXACTLY:

VULNERABILITY:
<short vulnerability name>

ROOT CAUSE:
<explanation>

SECURITY IMPACT:
<possible impact>

BEFORE:
<original vulnerable code>

AFTER:
<secure corrected code>

EXPLANATION:
<why the fix works>

CONFIDENCE:
<LOW / MEDIUM / HIGH>

If there is insufficient context, use:

CONFIDENCE:
LOW

and explain:

INSUFFICIENT CONTEXT
"""

    return generate_ai_response(prompt)