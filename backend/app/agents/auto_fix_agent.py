from app.services.groq_service import generate_ai_response


def generate_fix(
    vulnerability: dict,
    source_code: str,
) -> str:
    """
    Generate the complete corrected source file.

    The original repository is never modified.
    The AI returns the full corrected file content.
    """

    check_id = vulnerability.get(
        "check_id",
        "unknown",
    )

    message = (
        vulnerability.get("extra", {})
        .get("message", "")
    )

    file_path = vulnerability.get(
        "path",
        "",
    )

    line = (
        vulnerability.get("start", {})
        .get("line", "")
    )

    prompt = f"""
You are the Auto-Fix Agent of SentinelForge AI.

Your job is to fix the detected security vulnerability
in the provided source file.

IMPORTANT RULES:

1. Return the COMPLETE corrected source file.
2. Actually apply the security fix to the code.
3. Preserve all existing functionality.
4. Do not remove unrelated code.
5. Do not invent libraries or dependencies.
6. Make the smallest practical security change.
7. Keep imports and formatting unless a change is necessary.
8. Do not include explanations.
9. Do not include BEFORE/AFTER sections.
10. Do not use Markdown code fences.
11. Return ONLY the complete corrected source code.
12. Never modify the original repository.
13. If the context is insufficient to safely fix the issue,
    return the original source code unchanged.

VULNERABILITY
=============

Rule ID:
{check_id}

Message:
{message}

File:
{file_path}

Detected Line:
{line}

SOURCE FILE
===========

{source_code}

RETURN ONLY THE COMPLETE CORRECTED SOURCE FILE.
"""

    fixed_code = generate_ai_response(prompt)

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned empty code."
        )

    fixed_code = fixed_code.strip()

    # Remove accidental Markdown fences if the model adds them.
    if fixed_code.startswith("```"):
        lines = fixed_code.splitlines()

        if lines and lines[0].startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        fixed_code = "\n".join(lines).strip()

    return fixed_code