from app.services.groq_service import generate_ai_response


def generate_fix(
    vulnerability: dict,
    source_code: str,
) -> str:
    """
    SentinelForge AI - Auto-Fix Agent

    Generates a secure corrected version of the complete
    vulnerable source file.

    IMPORTANT:
    - The original repository is NEVER modified.
    - The original source code is only provided as context
      to the AI.
    - The AI must return the COMPLETE corrected source file.
    - The response is returned to main.py for parsing.
    """

    # ============================================================
    # GET VULNERABILITY INFORMATION
    # ============================================================

    check_id = vulnerability.get(
        "check_id",
        "unknown",
    )

    extra = vulnerability.get(
        "extra",
        {},
    )

    if not isinstance(extra, dict):
        extra = {}

    message = extra.get(
        "message",
        "",
    )

    severity = extra.get(
        "severity",
        "",
    )

    metadata = extra.get(
        "metadata",
        {},
    )

    if not isinstance(metadata, dict):
        metadata = {}

    cwe = metadata.get(
        "cwe",
        "",
    )

    if isinstance(cwe, list):
        cwe = ", ".join(
            str(item)
            for item in cwe
        )

    file_path = vulnerability.get(
        "path",
        "",
    )

    start = vulnerability.get(
        "start",
        {},
    )

    if not isinstance(start, dict):
        start = {}

    line = start.get(
        "line",
        "",
    )

    # ============================================================
    # VALIDATE SOURCE CODE
    # ============================================================

    if not source_code:
        raise ValueError(
            "Source code is empty."
        )

    if not source_code.strip():
        raise ValueError(
            "Source code is empty."
        )

    # ============================================================
    # AUTO-FIX PROMPT
    # ============================================================

    prompt = f"""
You are the Auto-Fix Agent of SentinelForge AI.

You are a senior application security engineer.

Your task is to securely fix ONE detected vulnerability
in the source code provided below.

The backend will use your response to create a NEW fixed
copy of the vulnerable file.

The original repository must NEVER be modified.

============================================================
STRICT REQUIREMENTS
============================================================

1. Return the COMPLETE corrected source file.

2. Actually fix the detected security vulnerability.

3. Preserve all existing application functionality.

4. Make the smallest practical security change.

5. Do NOT rewrite unrelated code.

6. Do NOT remove existing functionality.

7. Do NOT invent libraries, packages, APIs, or dependencies.

8. Prefer libraries and functions that already exist in
   the provided source code.

9. Add an import only when it is genuinely required for
   the security fix.

10. Preserve the existing file structure.

11. Preserve existing comments whenever possible.

12. Preserve formatting whenever possible.

13. Do not modify unrelated functions.

14. Do not change variable names unless necessary.

15. Do not change application behavior except where
    required to remove the vulnerability.

16. Do not return a code snippet.

17. Do not return only the changed function.

18. Return the COMPLETE FILE.

19. Do NOT use Markdown code fences.

20. Do NOT use triple backticks.

21. Do NOT add text before the source code.

22. Do NOT add text after the source code.

23. Do NOT include an explanation inside the source code.

24. Do NOT include VULNERABILITY, ROOT CAUSE,
    EXPLANATION, or CONFIDENCE sections inside the
    actual source code.

25. If the source code does not contain enough context
    to safely perform the fix, return the original source
    code unchanged.

26. Never claim that the repository was modified.

27. Never create a fake implementation.

28. The returned code must be directly usable as the
    contents of the original source file.

============================================================
DETECTED VULNERABILITY
============================================================

Rule ID:
{check_id}

Severity:
{severity}

CWE:
{cwe}

File:
{file_path}

Detected Line:
{line}

Security Scanner Message:
{message}

============================================================
ORIGINAL SOURCE CODE
============================================================

{source_code}

============================================================
HOW TO FIX
============================================================

Analyze the vulnerability carefully.

Identify the exact insecure operation.

Apply the appropriate secure coding practice.

Examples:

- SQL injection:
  Use parameterized queries instead of string
  concatenation or interpolation.

- Command injection:
  Avoid shell execution with untrusted input.
  Use safe APIs and argument lists.

- Path traversal:
  Validate and constrain filesystem paths.

- Hardcoded credentials:
  Move secrets to environment/configuration.

- Unsafe deserialization:
  Use safe parsing/deserialization mechanisms.

- Cross-site scripting:
  Properly encode or sanitize untrusted output.

- Improper authentication:
  Enforce proper authentication checks.

- Improper authorization:
  Verify that the current user has permission
  to perform the requested operation.

- Weak cryptography:
  Use secure cryptographic algorithms already
  supported by the project.

- Insecure random generation:
  Use a cryptographically secure random generator
  where security-sensitive randomness is required.

These are examples only.

Always analyze the actual source code and detected
vulnerability before making the change.

============================================================
OUTPUT REQUIREMENT
============================================================

Return ONLY the COMPLETE corrected source file.

No Markdown.

No code fences.

No explanation.

No headings.

No comments explaining the AI fix.

Just the complete corrected source code.

============================================================
"""

    # ============================================================
    # CALL GROQ AI SERVICE
    # ============================================================

    fixed_code = generate_ai_response(
        prompt
    )

    # ============================================================
    # VALIDATE AI RESPONSE
    # ============================================================

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned an empty response."
        )

    fixed_code = str(
        fixed_code
    ).strip()

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned an empty response."
        )

    # ============================================================
    # REMOVE ACCIDENTAL MARKDOWN FENCES
    # ============================================================

    lines = fixed_code.splitlines()

    if lines:
        first_line = lines[0].strip()

        if first_line.startswith("```"):
            lines = lines[1:]

    if lines:
        last_line = lines[-1].strip()

        if last_line == "```":
            lines = lines[:-1]

    fixed_code = "\n".join(
        lines
    ).strip()

    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned empty corrected code."
        )

    # ============================================================
    # RETURN COMPLETE SOURCE CODE
    # ============================================================

    return fixed_code