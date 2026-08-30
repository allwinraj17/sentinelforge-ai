from app.services.groq_service import generate_ai_response


def generate_fix(
    vulnerability: dict,
    source_code: str,
) -> str:
    """
    Generate a corrected version of the vulnerable source code.

    IMPORTANT:
    - The original repository is never modified.
    - The AI returns the complete corrected file content.
    - The backend will save the corrected content as a NEW file.
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

Your job is to FIX the vulnerable source code provided below.

The original repository MUST NOT be modified.

The backend will create a NEW fixed file from your response.

IMPORTANT RULES:

1. Actually fix the vulnerability.
2. Preserve the original functionality.
3. Make the smallest practical security change.
4. Do NOT rewrite unrelated code.
5. Do NOT invent libraries or dependencies.
6. Do NOT remove working functionality.
7. Use the libraries already present in the source code.
8. Return the COMPLETE corrected source file.
9. Do NOT return only a code snippet.
10. Do NOT include markdown code fences.
11. Do NOT include explanations outside the required format.
12. Never claim that the original repository was modified.
13. If the vulnerability cannot safely be fixed because context is insufficient, clearly say so.
14. Preserve imports and formatting wherever possible.
15. The returned FIXED_CODE must be directly usable as a source file.

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

ORIGINAL SOURCE CODE
====================

{source_code}

RETURN EXACTLY IN THIS FORMAT:

VULNERABILITY:
<short vulnerability name>

ROOT CAUSE:
<short explanation>

SECURITY IMPACT:
<short explanation>

FIXED_CODE:
<complete corrected source code>

EXPLANATION:
<short explanation of exactly what was changed>

CONFIDENCE:
<LOW / MEDIUM / HIGH>

If the source code does not contain enough context to safely fix the vulnerability:

CONFIDENCE:
LOW

and return:

FIXED_CODE:
NOT_AVAILABLE

Do not use markdown code fences around FIXED_CODE.
"""

    return generate_ai_response(prompt)