from typing import Dict, Any


# ============================================================
# RISK CONFIGURATION
# ============================================================

SEVERITY_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 1.0,
}


VULNERABILITY_RISK = {
    "sql-injection": {
        "impact": "Attackers may manipulate database queries, access unauthorized data, or modify records.",
        "exploitability": "HIGH",
        "recommendation": "Use parameterized queries or prepared statements instead of concatenating untrusted input into SQL queries.",
    },

    "xss": {
        "impact": "Attackers may inject malicious scripts into pages viewed by other users.",
        "exploitability": "HIGH",
        "recommendation": "Validate and sanitize user input and use proper output encoding.",
    },

    "command-injection": {
        "impact": "Attackers may execute unauthorized operating system commands on the server.",
        "exploitability": "HIGH",
        "recommendation": "Avoid executing shell commands with untrusted input. Use safe APIs and strict input validation.",
    },

    "path-traversal": {
        "impact": "Attackers may access files outside the intended application directory.",
        "exploitability": "HIGH",
        "recommendation": "Validate file paths and restrict access to an allowed directory.",
    },

    "hardcoded-secret": {
        "impact": "Exposed credentials or secrets may allow unauthorized access to systems and services.",
        "exploitability": "HIGH",
        "recommendation": "Remove secrets from source code and store them securely using environment variables or a secrets manager.",
    },

    "insecure-crypto": {
        "impact": "Weak cryptographic algorithms may allow attackers to recover sensitive information.",
        "exploitability": "MEDIUM",
        "recommendation": "Use modern cryptographic algorithms and secure libraries.",
    },

    "eval": {
        "impact": "Dynamic code execution may allow attackers to execute arbitrary code.",
        "exploitability": "HIGH",
        "recommendation": "Avoid eval() and other dynamic code execution functions with untrusted input.",
    },
}


# ============================================================
# FIND VULNERABILITY TYPE
# ============================================================

def identify_vulnerability(finding: Dict[str, Any]) -> str:
    """
    Identify the vulnerability category from Semgrep metadata.
    """

    metadata = finding.get("extra", {}).get("metadata", {})

    vulnerability_class = metadata.get("vulnerability_class")

    if isinstance(vulnerability_class, list):
        vulnerability_class = " ".join(vulnerability_class)

    if not vulnerability_class:
        vulnerability_class = ""

    value = vulnerability_class.lower()

    if "sql" in value:
        return "sql-injection"

    if "xss" in value or "cross-site scripting" in value:
        return "xss"

    if "command injection" in value:
        return "command-injection"

    if "path traversal" in value:
        return "path-traversal"

    if "secret" in value or "credential" in value:
        return "hardcoded-secret"

    if "crypto" in value:
        return "insecure-crypto"

    if "eval" in value or "code injection" in value:
        return "eval"

    # Also inspect the Semgrep message
    message = finding.get("extra", {}).get("message", "").lower()

    if "sql injection" in message:
        return "sql-injection"

    if "cross-site scripting" in message or "xss" in message:
        return "xss"

    if "command injection" in message:
        return "command-injection"

    if "path traversal" in message:
        return "path-traversal"

    return "security-vulnerability"


# ============================================================
# NORMALIZE SEVERITY
# ============================================================

def normalize_severity(finding: Dict[str, Any]) -> str:
    """
    Convert Semgrep severity into SentinelForge severity.
    """

    extra = finding.get("extra", {})

    severity = extra.get("severity")

    if not severity:
        severity = extra.get("metadata", {}).get("severity")

    if not severity:
        return "MEDIUM"

    severity = severity.upper()

    if severity == "ERROR":
        return "HIGH"

    if severity == "WARNING":
        return "MEDIUM"

    if severity == "INFO":
        return "LOW"

    if severity in SEVERITY_SCORES:
        return severity

    return "MEDIUM"


# ============================================================
# CALCULATE RISK SCORE
# ============================================================

def calculate_risk_score(
    severity: str,
    vulnerability_type: str,
) -> float:
    """
    Calculate a deterministic risk score from 1 to 10.
    """

    base_score = SEVERITY_SCORES.get(
        severity,
        5.0,
    )

    # High-impact vulnerability types receive a small boost.
    high_impact = {
        "sql-injection",
        "command-injection",
        "xss",
        "path-traversal",
        "hardcoded-secret",
        "eval",
    }

    if vulnerability_type in high_impact:
        base_score += 1.0

    return min(round(base_score, 1), 10.0)


# ============================================================
# CREATE RISK ASSESSMENT
# ============================================================

def assess_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a Semgrep finding into a SentinelForge
    risk assessment.
    """

    vulnerability_type = identify_vulnerability(
        finding
    )

    severity = normalize_severity(
        finding
    )

    risk_score = calculate_risk_score(
        severity,
        vulnerability_type,
    )

    risk_information = VULNERABILITY_RISK.get(
        vulnerability_type,
        {
            "impact": "This vulnerability may allow unauthorized behavior or expose sensitive application resources.",
            "exploitability": severity,
            "recommendation": "Review the vulnerable code and apply secure coding practices.",
        },
    )

    return {
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "risk_score": risk_score,
        "risk_level": severity,
        "impact": risk_information["impact"],
        "exploitability": risk_information["exploitability"],
        "recommendation": risk_information["recommendation"],
        "file": finding.get("path"),
        "line": finding.get("start", {}).get("line"),
        "cwe": finding.get("extra", {}).get(
            "metadata", {}
        ).get("cwe"),
    }


# ============================================================
# ASSESS ALL FINDINGS
# ============================================================

def assess_findings(
    findings: list,
) -> list:
    """
    Assess every Semgrep finding.
    """

    assessments = []

    for finding in findings:
        assessments.append(
            assess_finding(finding)
        )

    return assessments


# ============================================================
# OVERALL PROJECT RISK
# ============================================================

def calculate_overall_risk(
    assessments: list,
) -> Dict[str, Any]:
    """
    Calculate the overall security risk of the scanned code.
    """

    if not assessments:
        return {
            "overall_score": 0.0,
            "overall_level": "SECURE",
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    scores = [
        assessment["risk_score"]
        for assessment in assessments
    ]

    overall_score = max(scores)

    critical = sum(
        1
        for a in assessments
        if a["severity"] == "CRITICAL"
    )

    high = sum(
        1
        for a in assessments
        if a["severity"] == "HIGH"
    )

    medium = sum(
        1
        for a in assessments
        if a["severity"] == "MEDIUM"
    )

    low = sum(
        1
        for a in assessments
        if a["severity"] == "LOW"
    )

    if critical > 0:
        overall_level = "CRITICAL"
    elif high > 0:
        overall_level = "HIGH"
    elif medium > 0:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    return {
        "overall_score": overall_score,
        "overall_level": overall_level,
        "total_findings": len(assessments),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }