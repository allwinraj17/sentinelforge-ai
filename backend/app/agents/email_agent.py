from html import escape


# ============================================================
# PHASE 4 - EMAIL REPORT AGENT
# ============================================================

def _safe(value) -> str:
    """
    Safely convert a value to HTML-safe text.
    """
    if value is None:
        return ""

    return escape(str(value))


def _get_finding_value(finding: dict, key: str, default=""):
    """
    Safely read a value from a finding dictionary.
    """
    if not isinstance(finding, dict):
        return default

    value = finding.get(key, default)

    return value if value is not None else default


def generate_security_report_html(
    filename: str,
    findings: list,
    risk_assessments: list,
    overall_risk: dict,
    role: str = "developer",
    ai_analysis: str = "",
    fixes: list | None = None,
) -> str:
    """
    Generate the HTML email report for SentinelForge AI.

    The report is role-aware:

    Student:
        Simple explanation of the security problems,
        impact, attack possibility, prevention and
        what SentinelForge AI did.

    Developer:
        Technical vulnerability information including
        CWE, severity, file, line, Semgrep details,
        risk and remediation.

    Important:
        This function only generates the report.
        It does not send email.
    """

    # ========================================================
    # NORMALIZE INPUTS
    # ========================================================

    normalized_role = str(role).strip().lower()

    if normalized_role not in {
        "student",
        "developer",
    }:
        normalized_role = "developer"

    if not isinstance(findings, list):
        findings = []

    if not isinstance(risk_assessments, list):
        risk_assessments = []

    if not isinstance(overall_risk, dict):
        overall_risk = {}

    if not isinstance(fixes, list):
        fixes = []

    filename = _safe(filename)

    # ========================================================
    # OVERALL RISK INFORMATION
    # ========================================================

    overall_score = overall_risk.get(
        "score",
        overall_risk.get(
            "overall_score",
            0,
        ),
    )

    overall_level = overall_risk.get(
        "risk_level",
        overall_risk.get(
            "level",
            "Secure",
        ),
    )

    severity_counts = overall_risk.get(
        "severity_counts",
        {},
    )

    if not isinstance(
        severity_counts,
        dict,
    ):
        severity_counts = {}

    critical_count = severity_counts.get(
        "CRITICAL",
        0,
    )

    high_count = severity_counts.get(
        "HIGH",
        0,
    )

    medium_count = severity_counts.get(
        "MEDIUM",
        0,
    )

    low_count = severity_counts.get(
        "LOW",
        0,
    )

    # ========================================================
    # COMMON HTML
    # ========================================================

    html_parts = []

    html_parts.append(
        """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">

    <style>
        body {
            margin: 0;
            padding: 0;
            background: #f4f7fb;
            font-family: Arial, Helvetica, sans-serif;
            color: #1f2937;
        }

        .container {
            width: 100%;
            padding: 30px 15px;
            box-sizing: border-box;
        }

        .card {
            max-width: 850px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 14px;
            overflow: hidden;
            box-shadow: 0 6px 25px rgba(0, 0, 0, 0.08);
        }

        .header {
            padding: 30px;
            background: #111827;
            color: #ffffff;
        }

        .header h1 {
            margin: 0 0 8px 0;
            font-size: 28px;
        }

        .header p {
            margin: 0;
            color: #d1d5db;
            font-size: 14px;
        }

        .content {
            padding: 30px;
        }

        .summary-grid {
            display: table;
            width: 100%;
            border-spacing: 10px;
            margin: 0 -10px 20px -10px;
        }

        .summary-item {
            display: table-cell;
            width: 25%;
            background: #f9fafb;
            border-radius: 10px;
            padding: 16px;
            vertical-align: top;
        }

        .summary-title {
            color: #6b7280;
            font-size: 12px;
            margin-bottom: 6px;
        }

        .summary-value {
            color: #111827;
            font-size: 20px;
            font-weight: bold;
        }

        .section {
            margin-top: 28px;
        }

        .section h2 {
            margin: 0 0 14px 0;
            color: #111827;
            font-size: 20px;
        }

        .finding {
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            padding: 18px;
            margin-bottom: 14px;
            background: #ffffff;
        }

        .finding-title {
            font-size: 17px;
            font-weight: bold;
            color: #111827;
            margin-bottom: 10px;
        }

        .field {
            margin: 7px 0;
            font-size: 14px;
            line-height: 1.55;
        }

        .label {
            font-weight: bold;
            color: #374151;
        }

        .code {
            margin-top: 10px;
            padding: 14px;
            border-radius: 8px;
            background: #111827;
            color: #e5e7eb;
            font-family: Consolas, Monaco, monospace;
            font-size: 12px;
            line-height: 1.55;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .analysis {
            background: #f9fafb;
            border-left: 4px solid #4f46e5;
            padding: 16px;
            border-radius: 8px;
            white-space: pre-wrap;
            line-height: 1.65;
            font-size: 14px;
        }

        .fix {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 10px;
            padding: 16px;
            margin-top: 12px;
        }

        .note {
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-radius: 10px;
            padding: 15px;
            font-size: 13px;
            line-height: 1.6;
        }

        .footer {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            color: #6b7280;
            font-size: 12px;
            line-height: 1.6;
        }
    </style>
</head>

<body>
<div class="container">
<div class="card">

<div class="header">
    <h1>SentinelForge AI</h1>
    <p>Automated Repository Security Analysis Report</p>
</div>

<div class="content">
"""
    )

    # ========================================================
    # INTRO
    # ========================================================

    if normalized_role == "student":
        intro_text = (
            "Your repository was analyzed by SentinelForge AI. "
            "This report explains the detected security issues "
            "in a simple and educational manner."
        )
    else:
        intro_text = (
            "Your repository was analyzed by SentinelForge AI "
            "using automated security scanning, risk assessment "
            "and AI-assisted security analysis."
        )

    html_parts.append(
        f"""
<p style="font-size:15px; line-height:1.7;">
    {intro_text}
</p>
"""
    )

    # ========================================================
    # REPOSITORY SUMMARY
    # ========================================================

    html_parts.append(
        f"""
<div class="section">
    <h2>Repository Summary</h2>

    <div class="summary-grid">

        <div class="summary-item">
            <div class="summary-title">Repository</div>
            <div class="summary-value"
                 style="font-size:15px;">
                {filename}
            </div>
        </div>

        <div class="summary-item">
            <div class="summary-title">Vulnerabilities</div>
            <div class="summary-value">
                {_safe(len(findings))}
            </div>
        </div>

        <div class="summary-item">
            <div class="summary-title">Risk Score</div>
            <div class="summary-value">
                {_safe(overall_score)}
            </div>
        </div>

        <div class="summary-item">
            <div class="summary-title">Risk Level</div>
            <div class="summary-value"
                 style="font-size:16px;">
                {_safe(overall_level)}
            </div>
        </div>

    </div>
</div>
"""
    )

    # ========================================================
    # SEVERITY SUMMARY
    # ========================================================

    html_parts.append(
        f"""
<div class="section">
    <h2>Severity Summary</h2>

    <div class="summary-grid">

        <div class="summary-item">
            <div class="summary-title">Critical</div>
            <div class="summary-value">
                {_safe(critical_count)}
            </div>
        </div>

        <div class="summary-item">
            <div class="summary-title">High</div>
            <div class="summary-value">
                {_safe(high_count)}
            </div>
        </div>

        <div class="summary-item">
            <div class="summary-title">Medium</div>
            <div class="summary-value">
                {_safe(medium_count)}
            </div>
        </div>

        <div class="summary-item">
            <div class="summary-title">Low</div>
            <div class="summary-value">
                {_safe(low_count)}
            </div>
        </div>

    </div>
</div>
"""
    )

    # ========================================================
    # VULNERABILITY DETAILS
    # ========================================================

    html_parts.append(
        """
<div class="section">
    <h2>Security Findings</h2>
"""
    )

    if not findings:

        html_parts.append(
            """
<div class="note">
    No security vulnerabilities were detected during
    the security scanning stage.
</div>
"""
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            if not isinstance(
                finding,
                dict,
            ):
                continue

            assessment = {}

            if (
                index - 1
                < len(risk_assessments)
            ):
                candidate = risk_assessments[
                    index - 1
                ]

                if isinstance(
                    candidate,
                    dict,
                ):
                    assessment = candidate

            # ------------------------------------------------
            # BASIC INFORMATION
            # ------------------------------------------------

            check_id = _get_finding_value(
                finding,
                "check_id",
                "Unknown",
            )

            path = _get_finding_value(
                finding,
                "path",
                "Unknown",
            )

            start = finding.get(
                "start",
                {},
            )

            if not isinstance(
                start,
                dict,
            ):
                start = {}

            line = start.get(
                "line",
                _get_finding_value(
                    finding,
                    "line",
                    "Unknown",
                ),
            )

            extra = finding.get(
                "extra",
                {},
            )

            if not isinstance(
                extra,
                dict,
            ):
                extra = {}

            message = extra.get(
                "message",
                "Security issue detected.",
            )

            severity = (
                assessment.get(
                    "severity",
                    extra.get(
                        "severity",
                        "Unknown",
                    ),
                )
            )

            vulnerability_type = assessment.get(
                "vulnerability_type",
                extra.get(
                    "vulnerability_class",
                    "Security vulnerability",
                ),
            )

            cwe = assessment.get(
                "cwe",
                "",
            )

            risk_score = assessment.get(
                "risk_score",
                "",
            )

            risk_level = assessment.get(
                "risk_level",
                "",
            )

            impact = assessment.get(
                "impact",
                "",
            )

            exploitability = assessment.get(
                "exploitability",
                "",
            )

            recommendation = assessment.get(
                "recommendation",
                "",
            )

            source_code = finding.get(
                "source_code",
                "",
            )

            # ------------------------------------------------
            # STUDENT REPORT
            # ------------------------------------------------

            if normalized_role == "student":

                html_parts.append(
                    f"""
<div class="finding">

    <div class="finding-title">
        Vulnerability {index}:
        {_safe(vulnerability_type)}
    </div>

    <div class="field">
        <span class="label">Where:</span>
        {_safe(path)}
        at line
        {_safe(line)}
    </div>

    <div class="field">
        <span class="label">What happened:</span>
        {_safe(message)}
    </div>

    <div class="field">
        <span class="label">Why it matters:</span>
        {_safe(impact)}
    </div>

    <div class="field">
        <span class="label">Possible attack path:</span>
        {_safe(exploitability)}
    </div>

    <div class="field">
        <span class="label">How to prevent it:</span>
        {_safe(recommendation)}
    </div>

    <div class="field">
        <span class="label">Semgrep rule:</span>
        {_safe(check_id)}
    </div>

"""
                )

                if source_code:
                    html_parts.append(
                        f"""
    <div class="field">
        <span class="label">
            Relevant source context:
        </span>
    </div>

    <div class="code">
{_safe(source_code)}
    </div>
"""
                    )

                html_parts.append(
                    """
</div>
"""
                )

            # ------------------------------------------------
            # DEVELOPER REPORT
            # ------------------------------------------------

            else:

                html_parts.append(
                    f"""
<div class="finding">

    <div class="finding-title">
        Finding {index}:
        {_safe(vulnerability_type)}
    </div>

    <div class="field">
        <span class="label">
            Semgrep Rule:
        </span>
        {_safe(check_id)}
    </div>

    <div class="field">
        <span class="label">
            Message:
        </span>
        {_safe(message)}
    </div>

    <div class="field">
        <span class="label">
            File:
        </span>
        {_safe(path)}
    </div>

    <div class="field">
        <span class="label">
            Line:
        </span>
        {_safe(line)}
    </div>

    <div class="field">
        <span class="label">
            Severity:
        </span>
        {_safe(severity)}
    </div>

    <div class="field">
        <span class="label">
            CWE:
        </span>
        {_safe(cwe)}
    </div>

    <div class="field">
        <span class="label">
            Risk Score:
        </span>
        {_safe(risk_score)}
    </div>

    <div class="field">
        <span class="label">
            Risk Level:
        </span>
        {_safe(risk_level)}
    </div>

    <div class="field">
        <span class="label">
            Impact:
        </span>
        {_safe(impact)}
    </div>

    <div class="field">
        <span class="label">
            Exploitability:
        </span>
        {_safe(exploitability)}
    </div>

    <div class="field">
        <span class="label">
            Recommended Remediation:
        </span>
        {_safe(recommendation)}
    </div>

"""
                )

                if source_code:
                    html_parts.append(
                        f"""
    <div class="field">
        <span class="label">
            Source Context:
        </span>
    </div>

    <div class="code">
{_safe(source_code)}
    </div>
"""
                    )

                html_parts.append(
                    """
</div>
"""
                )

    html_parts.append(
        """
</div>
"""
    )

    # ========================================================
    # AI ANALYSIS
    # ========================================================

    if ai_analysis:

        html_parts.append(
            f"""
<div class="section">
    <h2>
        AI Security Analysis
    </h2>

    <div class="analysis">
{_safe(ai_analysis)}
    </div>
</div>
"""
        )

    # ========================================================
    # AUTO-FIX SUMMARY
    # ========================================================

    html_parts.append(
        """
<div class="section">
    <h2>AI Auto-Fix</h2>
"""
    )

    successful_fixes = 0

    for fix in fixes:

        if not isinstance(
            fix,
            dict,
        ):
            continue

        success = bool(
            fix.get(
                "success",
                False,
            )
        )

        if success:
            successful_fixes += 1

    if successful_fixes:

        html_parts.append(
            f"""
<div class="fix">

    <div class="field">
        <span class="label">
            Auto-Fix Results:
        </span>
        {_safe(successful_fixes)}
        security fix(s) were generated.
    </div>

    <div class="field">
        SentinelForge AI generated corrected copies
        of affected source files. The original uploaded
        repository remains unchanged.
    </div>

    <div class="field">
        <strong>
            Important:
        </strong>
        The generated fixes are not described as
        security-verified because Phase 4 does not
        perform a second security scan.
    </div>

</div>
"""
        )

    else:

        html_parts.append(
            """
<div class="note">
    No AI-generated fix was included in this report.
</div>
"""
        )

    html_parts.append(
        """
</div>
"""
    )

    # ========================================================
    # VALIDATION NOTICE
    # ========================================================

    html_parts.append(
        """
<div class="section">
    <h2>Validation Status</h2>

    <div class="note">
        SentinelForge AI completed its security analysis,
        risk assessment and AI remediation preparation.
        Phase 4 does not perform a second security scan
        after auto-fix generation, so the generated fixes
        are not claimed as security-verified.
    </div>
</div>
"""
    )

    # ========================================================
    # FOOTER
    # ========================================================

    html_parts.append(
        """
<div class="footer">
    <strong>SentinelForge AI</strong><br>
    Autonomous AI-powered repository security analysis.<br>
    This report was generated automatically.
</div>

</div>
</div>
</div>

</body>
</html>
"""
    )

    return "".join(html_parts)