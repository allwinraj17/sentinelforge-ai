from html import escape


def generate_security_report_html(
    filename: str,
    findings: list,
    risk_assessments: list,
    overall_risk: dict,
) -> str:
    """
    Generate a professional HTML security report.
    """

    overall_level = overall_risk.get(
        "overall_level",
        "UNKNOWN",
    )

    overall_score = overall_risk.get(
        "overall_score",
        0,
    )

    total_findings = overall_risk.get(
        "total_findings",
        len(findings),
    )

    critical = overall_risk.get(
        "critical",
        0,
    )

    high = overall_risk.get(
        "high",
        0,
    )

    medium = overall_risk.get(
        "medium",
        0,
    )

    low = overall_risk.get(
        "low",
        0,
    )

    # ========================================================
    # FINDINGS HTML
    # ========================================================

    findings_html = ""

    for index, finding in enumerate(findings, start=1):

        extra = finding.get("extra", {})

        message = extra.get(
            "message",
            "Security vulnerability detected.",
        )

        check_id = finding.get(
            "check_id",
            "Unknown",
        )

        path = finding.get(
            "path",
            "Unknown",
        )

        start = finding.get(
            "start",
            {},
        )

        line = start.get(
            "line",
            "Unknown",
        )

        severity = finding.get(
            "severity",
            "UNKNOWN",
        )

        findings_html += f"""
        <div style="
            margin-bottom:20px;
            padding:20px;
            border:1px solid #e5e7eb;
            border-radius:10px;
            background:#ffffff;
        ">

            <h3 style="
                margin-top:0;
                color:#111827;
            ">
                {index}. {escape(check_id)}
            </h3>

            <p>
                <strong>Severity:</strong>
                {escape(str(severity))}
            </p>

            <p>
                <strong>File:</strong>
                {escape(str(path))}
            </p>

            <p>
                <strong>Line:</strong>
                {escape(str(line))}
            </p>

            <p>
                <strong>Description:</strong><br>
                {escape(str(message))}
            </p>

        </div>
        """

    # ========================================================
    # RISK ASSESSMENTS HTML
    # ========================================================

    risk_html = ""

    for index, risk in enumerate(
        risk_assessments,
        start=1,
    ):

        vulnerability_type = risk.get(
            "vulnerability_type",
            "Unknown",
        )

        severity = risk.get(
            "severity",
            "Unknown",
        )

        score = risk.get(
            "risk_score",
            0,
        )

        impact = risk.get(
            "impact",
            "Not specified.",
        )

        exploitability = risk.get(
            "exploitability",
            "Not specified.",
        )

        recommendation = risk.get(
            "recommendation",
            "No recommendation available.",
        )

        risk_html += f"""
        <div style="
            margin-bottom:20px;
            padding:20px;
            border:1px solid #e5e7eb;
            border-radius:10px;
            background:#f9fafb;
        ">

            <h3 style="margin-top:0;">
                {index}. {escape(str(vulnerability_type))}
            </h3>

            <p>
                <strong>Severity:</strong>
                {escape(str(severity))}
            </p>

            <p>
                <strong>Risk Score:</strong>
                {escape(str(score))}/10
            </p>

            <p>
                <strong>Exploitability:</strong>
                {escape(str(exploitability))}
            </p>

            <p>
                <strong>Impact:</strong><br>
                {escape(str(impact))}
            </p>

            <p>
                <strong>Recommendation:</strong><br>
                {escape(str(recommendation))}
            </p>

        </div>
        """

    # ========================================================
    # COMPLETE REPORT
    # ========================================================

    html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>SentinelForge Security Report</title>

</head>

<body style="
    margin:0;
    padding:0;
    background:#f3f4f6;
    font-family:Arial,Helvetica,sans-serif;
    color:#111827;
">

<div style="
    max-width:800px;
    margin:30px auto;
    background:#ffffff;
    border-radius:14px;
    overflow:hidden;
">

    <!-- HEADER -->

    <div style="
        padding:30px;
        background:#111827;
        color:#ffffff;
    ">

        <h1 style="
            margin:0;
            font-size:28px;
        ">
            SentinelForge AI
        </h1>

        <p style="
            margin:8px 0 0;
            color:#d1d5db;
        ">
            Security Analysis Report
        </p>

    </div>


    <!-- SUMMARY -->

    <div style="padding:30px;">

        <h2>Scan Summary</h2>

        <p>
            <strong>Repository:</strong>
            {escape(str(filename))}
        </p>

        <p>
            <strong>Overall Risk:</strong>
            {escape(str(overall_level))}
        </p>

        <p>
            <strong>Risk Score:</strong>
            {escape(str(overall_score))}/10
        </p>

        <p>
            <strong>Total Findings:</strong>
            {escape(str(total_findings))}
        </p>


        <!-- COUNTS -->

        <table style="
            width:100%;
            border-collapse:collapse;
            margin-top:20px;
        ">

            <tr>

                <td style="
                    padding:15px;
                    border:1px solid #e5e7eb;
                ">
                    <strong>Critical</strong><br>
                    {critical}
                </td>

                <td style="
                    padding:15px;
                    border:1px solid #e5e7eb;
                ">
                    <strong>High</strong><br>
                    {high}
                </td>

                <td style="
                    padding:15px;
                    border:1px solid #e5e7eb;
                ">
                    <strong>Medium</strong><br>
                    {medium}
                </td>

                <td style="
                    padding:15px;
                    border:1px solid #e5e7eb;
                ">
                    <strong>Low</strong><br>
                    {low}
                </td>

            </tr>

        </table>


        <!-- SECURITY FINDINGS -->

        <h2 style="
            margin-top:35px;
        ">
            Security Findings
        </h2>

        {findings_html}


        <!-- RISK ASSESSMENT -->

        <h2 style="
            margin-top:35px;
        ">
            Risk Assessment
        </h2>

        {risk_html}


        <!-- FOOTER -->

        <div style="
            margin-top:30px;
            padding-top:20px;
            border-top:1px solid #e5e7eb;
            color:#6b7280;
            font-size:13px;
        ">

            <p>
                This report was automatically generated by
                SentinelForge AI.
            </p>

            <p>
                The report provides security analysis and
                recommendations. Review findings before
                deploying code to production.
            </p>

        </div>

    </div>

</div>

</body>

</html>
"""

    return html