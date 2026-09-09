import json

from app.services.groq_service import generate_ai_response


# ============================================================
# SECURITY ANALYSIS AGENT
# ============================================================

def analyze_security_findings(
    findings: list,
    role: str = "developer",
) -> str:
    """
    Analyze security findings using Groq.

    This is the Phase 4 Security Analysis Agent.

    Important:
    - Does not modify the repository.
    - Does not generate fixes.
    - Uses only the findings supplied by SentinelForge.
    - Produces role-aware security analysis.
    """

    # --------------------------------------------------------
    # VALIDATE FINDINGS
    # --------------------------------------------------------

    if not findings:
        return (
            "No security vulnerabilities were detected. "
            "The repository passed the current SentinelForge "
            "security checks."
        )

    # --------------------------------------------------------
    # NORMALIZE ROLE
    # --------------------------------------------------------

    normalized_role = str(
        role or "developer"
    ).strip().lower()

    if normalized_role not in {
        "student",
        "developer",
    }:
        normalized_role = "developer"

    # --------------------------------------------------------
    # PREPARE FINDINGS DATA
    # --------------------------------------------------------

    findings_json = json.dumps(
        findings,
        indent=2,
        default=str,
    )

    # --------------------------------------------------------
    # STUDENT PROMPT
    # --------------------------------------------------------

    if normalized_role == "student":

        prompt = f"""
You are the Security Education Agent of SentinelForge AI.

A software repository was scanned by SentinelForge AI and
the following security findings were detected.

SECURITY FINDINGS:
{findings_json}

Your job is to explain the detected vulnerabilities in
simple, educational language for a student.

For EACH vulnerability explain:

1. What is the vulnerability?
2. Where was it detected?
3. Why did it happen?
4. How could an attacker potentially exploit it?
5. What could happen if it is not fixed?
6. How should a developer prevent or fix it?
7. What security lesson can the student learn?

After explaining each vulnerability, provide:

- Overall security condition
- Most important issue to fix first
- Simple secure-coding recommendations

IMPORTANT RULES:

- Only discuss vulnerabilities present in the supplied findings.
- Do not invent vulnerabilities.
- Do not claim that anything has been fixed.
- Do not claim that SentinelForge verified a fix.
- Do not say that the repository was modified.
- Do not provide fake technical details.
- Keep explanations accurate and beginner-friendly.
"""

    # --------------------------------------------------------
    # DEVELOPER PROMPT
    # --------------------------------------------------------

    else:

        prompt = f"""
You are the Senior Security Analysis Agent of SentinelForge AI.

A software repository was scanned by SentinelForge AI and
the following security findings were detected.

SECURITY FINDINGS:
{findings_json}

Provide a professional technical security assessment.

For EACH vulnerability explain:

1. Vulnerability name
2. CWE if available
3. Severity
4. Risk
5. Affected file and line
6. Semgrep rule
7. Why the vulnerable pattern is insecure
8. Root cause
9. Potential attack scenario
10. Security impact
11. Exploitability
12. Recommended remediation
13. Secure coding recommendation

Then provide:

- Overall security assessment
- Highest-priority vulnerabilities
- Recommended remediation order
- General repository security recommendations

IMPORTANT RULES:

- Base the analysis strictly on the supplied findings.
- Do not invent vulnerabilities.
- Do not modify files.
- Do not generate source-code fixes in this step.
- Do not claim that vulnerabilities are fixed.
- Do not claim that a fix has been verified.
- Do not claim that a second scan was performed.
- Do not claim that the repository was modified.
- Clearly distinguish detected facts from security recommendations.
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

    analysis = str(
        analysis
    ).strip()

    if not analysis:
        raise RuntimeError(
            "Groq returned an empty security analysis."
        )

    return analysis


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

async def analyze_with_groq(
    findings: list,
) -> str:
    """
    Backward-compatible wrapper for the previous Phase 3 API.

    Defaults to developer-oriented analysis.
    """

    return analyze_security_findings(
        findings=findings,
        role="developer",
    )