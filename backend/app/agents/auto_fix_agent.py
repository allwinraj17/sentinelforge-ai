from app.services.groq_service import generate_ai_response


# ============================================================
# PHASE 4 - AUTO-FIX AGENT
# ============================================================

def generate_fix(
    vulnerability: dict,
    source_code: str,
) -> str:
    """
    SentinelForge AI Phase 4 Auto-Fix Agent.

    Generates a complete corrected copy of one vulnerable
    source file.

    IMPORTANT:
    - Never modifies the original repository.
    - Never writes directly to the user's uploaded files.
    - Returns only corrected source code.
    - Preserves existing functionality whenever possible.
    """

    if not isinstance(vulnerability, dict):
        raise ValueError(
            "Invalid vulnerability data."
        )

    if not isinstance(source_code, str):
        raise ValueError(
            "Source code must be a string."
        )

    if not source_code.strip():
        raise ValueError(
            "Source code is empty."
        )

    # ========================================================
    # EXTRACT FINDING INFORMATION
    # ========================================================

    check_id = vulnerability.get(
        "check_id",
        "unknown",
    )

    file_path = vulnerability.get(
        "path",
        "unknown",
    )

    start = vulnerability.get(
        "start",
        {},
    )

    if not isinstance(start, dict):
        start = {}

    line = start.get(
        "line",
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
        "Security vulnerability detected.",
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

    vulnerability_class = metadata.get(
        "vulnerability_class",
        "",
    )

    if isinstance(vulnerability_class, list):
        vulnerability_class = ", ".join(
            str(item)
            for item in vulnerability_class
        )

    # ========================================================
    # STRICT AUTO-FIX PROMPT
    # ========================================================

    prompt = f"""
You are the Auto-Fix Agent of SentinelForge AI.

You are a senior application security engineer.

Your task is to fix ONE specific security vulnerability
in the source file supplied below.

The backend will use your response as the complete contents
of a NEW corrected copy of the vulnerable source file.

The original repository MUST NOT be modified.

============================================================
DETECTED SECURITY ISSUE
============================================================

Semgrep Rule:
{check_id}

Vulnerability Class:
{vulnerability_class}

Severity:
{severity}

CWE:
{cwe}

File:
{file_path}

Detected Line:
{line}

Semgrep Message:
{message}

============================================================
STRICT REQUIREMENTS
============================================================

1. Return the COMPLETE corrected source file.

2. Actually address the detected vulnerability.

3. Preserve the application's existing functionality.

4. Make the smallest practical security change.

5. Do not rewrite unrelated code.

6. Do not remove unrelated functionality.

7. Do not invent dependencies.

8. Do not invent libraries.

9. Prefer libraries already used by the source file.

10. Add an import only when genuinely necessary.

11. Preserve the existing file structure.

12. Preserve existing comments whenever practical.

13. Preserve existing formatting whenever practical.

14. Do not rename variables unless required.

15. Do not change unrelated behavior.

16. Do not return a snippet.

17. Do not return only the vulnerable function.

18. Do not return a diff.

19. Do not return an explanation.

20. Do not use Markdown code fences.

21. Do not use triple backticks.

22. Do not put headings before the source code.

23. Do not put explanations after the source code.

24. Return ONLY the complete corrected source file.

25. If there is insufficient context to safely fix the
    vulnerability, return the ORIGINAL SOURCE CODE
    unchanged rather than inventing a solution.

26. Never claim the repository was modified.

27. Never claim the fix was verified.

28. Never claim a second security scan was performed.

============================================================
SECURITY FIX GUIDANCE
============================================================

Use the actual vulnerability and source code as the source
of truth.

Examples of secure remediation:

SQL Injection:
- Use parameterized queries.
- Do not concatenate untrusted input into SQL.

Command Injection:
- Avoid shell execution with untrusted input.
- Prefer safe APIs and explicit argument lists.

Path Traversal:
- Validate and constrain filesystem paths.
- Ensure user-controlled paths cannot escape the
  intended directory.

Hardcoded Secrets:
- Do not leave credentials in source code.
- Use environment/configuration mechanisms already
  supported by the application.

Cross-Site Scripting:
- Properly encode or sanitize untrusted output.

Unsafe Deserialization:
- Use safe parsing mechanisms.

Weak Cryptography:
- Replace insecure cryptographic usage with an
  appropriate secure implementation already compatible
  with the project.

Insecure Randomness:
- Use a cryptographically secure random generator
  when security-sensitive randomness is required.

These are examples only.

Always analyze the actual source code and Semgrep finding.

============================================================
ORIGINAL SOURCE FILE
============================================================

{source_code}

============================================================
FINAL OUTPUT CONTRACT
============================================================

Return ONLY the complete corrected source file.

No Markdown.
No code fences.
No explanation.
No headings.
No analysis.
No FIXED_CODE label.
No EXPLANATION label.

Only the corrected source file.
"""

    # ========================================================
    # CALL GROQ
    # ========================================================

    fixed_code = generate_ai_response(
        prompt
    )

    # ========================================================
    # VALIDATE RESPONSE
    # ========================================================

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

    # ========================================================
    # REMOVE ACCIDENTAL MARKDOWN FENCES
    # ========================================================

    lines = fixed_code.splitlines()

    if lines:
        first_line = lines[0].strip()

        if first_line.startswith("```"):
            lines = lines[1:]

    if lines:
        last_line = lines[-1].strip()

        if lines[-1].strip() == "```":
            lines = lines[:-1]

    fixed_code = "\n".join(
        lines
    ).strip()

    # ========================================================
    # HANDLE AI FAILURE RESPONSES
    # ========================================================

    invalid_values = {
        "",
        "NOT_AVAILABLE",
        "NOT AVAILABLE",
        "UNABLE_TO_FIX",
        "UNABLE TO FIX",
    }

    if fixed_code.strip().upper() in invalid_values:
        raise ValueError(
            "Auto-Fix Agent could not safely generate a fix."
        )

    # ========================================================
    # FINAL VALIDATION
    # ========================================================

    if not fixed_code:
        raise ValueError(
            "Auto-Fix Agent returned empty corrected code."
        )

    return fixed_code