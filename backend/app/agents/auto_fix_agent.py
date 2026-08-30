from app.services.groq_service import generate_ai_response


def generate_fix(
    vulnerability: dict,
    source_code: str,
) -> str:
    """
    Generate the complete corrected source file.

    The original repository is never modified.

    Returns:
        Complete corrected source code as a string.
    """

    if not source_code or not source_code.strip():
        raise ValueError(
            "Source code is empty."
        )

    # ========================================================
    # VULNERABILITY INFORMATION
    # ========================================================

    check_id = vulnerability.get(
        "check_id",
        "unknown",
    )

    message = (
        vulnerability
        .get("extra", {})
        .get("message", "")
    )

    file_path = vulnerability.get(
        "path",
        "",
    )

    line = (
        vulnerability
        .get("start", {})
        .get("line", "")
    )

    # ========================================================
    # ADDITIONAL SECURITY INFORMATION
    # ========================================================

    metadata = (
        vulnerability
        .get("extra", {})
        .get("metadata", {})
    )

    vulnerability_class = metadata.get(
        "vulnerability_class",
        "",
    )

    cwe = metadata.get(
        "cwe",
        "",
    )

    # ========================================================
    # AUTO-FIX PROMPT
    # ========================================================

    prompt = f"""
You are the Auto-Fix Agent of SentinelForge AI,
an AI-powered multi-agent cybersecurity platform.

Your task is to repair ONE security vulnerability
in the provided source file.

============================================================
STRICT REQUIREMENTS
============================================================

1. Return the COMPLETE corrected source file.

2. Actually fix the detected vulnerability.

3. Preserve the original functionality.

4. Make the smallest practical security change.

5. Do NOT remove unrelated code.

6. Do NOT invent libraries.

7. Do NOT add unnecessary dependencies.

8. Keep existing imports unless a change is required.

9. Preserve formatting where practical.

10. Do NOT explain the fix.

11. Do NOT return analysis.

12. Do NOT return BEFORE/AFTER sections.

13. Do NOT return Markdown code fences.

14. Do NOT return headings.

15. Do NOT return phrases such as:
    FIXED_CODE:
    EXPLANATION:
    BEFORE:
    AFTER:

16. Return ONLY the complete corrected source code.

17. Never modify the original repository.

18. If the vulnerability cannot be safely fixed from the
    available source context, return the original source code
    unchanged rather than inventing code.

============================================================
VULNERABILITY INFORMATION
============================================================

Rule ID:
{check_id}

Vulnerability:
{vulnerability_class}

CWE:
{cwe}

Message:
{message}

File:
{file_path}

Detected Line:
{line}

============================================================
SOURCE CODE
============================================================

{source_code}

============================================================
FINAL INSTRUCTION
============================================================

Return ONLY the complete corrected source file.

No Markdown.

No explanation.

No headings.

No FIXED_CODE label.

No EXPLANATION label.

The first character of your response must be the first
character of the corrected source file.
"""

    # ========================================================
    # CALL GROQ AI
    # ========================================================

    fixed_code = generate_ai_response(prompt)

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned empty code."
        )

    fixed_code = str(
        fixed_code
    ).strip()

    # ========================================================
    # REMOVE MARKDOWN FENCES
    # ========================================================

    if fixed_code.startswith("```"):

        lines = fixed_code.splitlines()

        if lines:
            lines = lines[1:]

        if (
            lines
            and lines[-1].strip() == "```"
        ):
            lines = lines[:-1]

        fixed_code = "\n".join(
            lines
        ).strip()

    # ========================================================
    # REMOVE ACCIDENTAL LABELS
    # ========================================================

    if fixed_code.startswith(
        "FIXED_CODE:"
    ):

        fixed_code = (
            fixed_code[
                len("FIXED_CODE:"):
            ]
            .strip()
        )

    # ========================================================
    # FINAL VALIDATION
    # ========================================================

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent produced empty source code."
        )

    return fixed_code