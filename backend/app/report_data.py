"""
SentinelForge AI - Report Data Helpers

Provides small helpers for combining dependency, secret,
Auto-Fix, validation and vulnerability information into
one presentation-ready structure.

This module does not perform scanning or security decisions.
"""

from __future__ import annotations


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _value(data, keys, default=""):
    data = _dict(data)

    for key in keys:
        value = data.get(key)

        if value is not None and value != "":
            return value

    return default


def normalize_secret_report(secret_result):
    """
    Normalize the Secret Detection Agent output.

    Secret values should already be masked by the secret agent.
    This helper never attempts to recover or expose original secrets.
    """

    result = _dict(secret_result)

    findings = _list(
        result.get("findings")
    )

    normalized = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        finding = _dict(finding)

        normalized.append(
            {
                "secret_id": _value(
                    finding,
                    [
                        "secret_id",
                        "finding_id",
                        "id",
                    ],
                    f"S{index:03d}",
                ),
                "type": _value(
                    finding,
                    [
                        "type",
                        "secret_type",
                        "category",
                    ],
                    "Potential Secret",
                ),
                "file": _value(
                    finding,
                    [
                        "file",
                        "path",
                    ],
                    "Unknown",
                ),
                "line": _value(
                    finding,
                    ["line"],
                    "Unknown",
                ),
                "masked_value": _value(
                    finding,
                    [
                        "masked_value",
                        "masked_secret",
                        "masked",
                    ],
                    "",
                ),
                "message": _value(
                    finding,
                    ["message"],
                    "Potential secret detected.",
                ),
                "severity": _value(
                    finding,
                    ["severity"],
                    "HIGH",
                ),
            }
        )

    return {
        "count": len(normalized),
        "findings": normalized,
    }


def normalize_dependency_report(
    dependency_result,
):
    """
    Normalize Dependency Vulnerability Agent output.
    """

    result = _dict(
        dependency_result
    )

    vulnerabilities = _list(
        result.get(
            "vulnerabilities"
        )
    )

    normalized = []

    for index, vulnerability in enumerate(
        vulnerabilities,
        start=1,
    ):
        vulnerability = _dict(
            vulnerability
        )

        aliases = vulnerability.get(
            "aliases",
            [],
        )

        if not isinstance(
            aliases,
            list,
        ):
            aliases = []

        normalized.append(
            {
                "dependency_id": _value(
                    vulnerability,
                    [
                        "dependency_id",
                        "id",
                    ],
                    f"D{index:03d}",
                ),
                "package": _value(
                    vulnerability,
                    [
                        "package",
                        "package_name",
                        "name",
                    ],
                    "Unknown",
                ),
                "ecosystem": _value(
                    vulnerability,
                    ["ecosystem"],
                    "Unknown",
                ),
                "version": _value(
                    vulnerability,
                    [
                        "version",
                        "installed_version",
                    ],
                    "Unknown",
                ),
                "vulnerability_id": _value(
                    vulnerability,
                    [
                        "vulnerability_id",
                        "osv_id",
                        "id",
                    ],
                    "Unknown",
                ),
                "aliases": aliases,
                "severity": _value(
                    vulnerability,
                    ["severity"],
                    "Unknown",
                ),
                "summary": _value(
                    vulnerability,
                    [
                        "summary",
                        "message",
                        "description",
                    ],
                    "Dependency vulnerability detected.",
                ),
                "fixed_version": _value(
                    vulnerability,
                    [
                        "fixed_version",
                        "fixed",
                    ],
                    "",
                ),
                "source_file": _value(
                    vulnerability,
                    [
                        "source_file",
                        "file",
                        "path",
                    ],
                    "Unknown",
                ),
            }
        )

    return {
        "count": len(normalized),
        "vulnerabilities": normalized,
        "dependency_files": _list(
            result.get(
                "dependency_files"
            )
        ),
    }


def normalize_autofix_report(
    fixes,
):
    """
    Normalize Auto-Fix results for dashboard/PDF display.
    """

    fixes = _list(fixes)

    normalized = []

    for index, fix in enumerate(
        fixes,
        start=1,
    ):
        fix = _dict(fix)

        finding_id = _value(
            fix,
            [
                "finding_id",
                "findingId",
            ],
            f"F{index:03d}",
        )

        success = bool(
            fix.get(
                "success",
                False,
            )
        )

        validation = _dict(
            fix.get(
                "validation"
            )
        )

        normalized.append(
            {
                "finding_id": str(
                    finding_id
                ),
                "success": success,
                "status": (
                    "Generated"
                    if success
                    else "Failed"
                ),
                "file": _value(
                    fix,
                    [
                        "path",
                        "file",
                    ],
                    "Unknown",
                ),
                "original_code": _value(
                    fix,
                    [
                        "original_code",
                        "source_code",
                    ],
                    "",
                ),
                "fixed_code": _value(
                    fix,
                    [
                        "fixed_code",
                        "ai_fixed_code",
                        "fixed_source_code",
                    ],
                    "",
                ),
                "validation": validation,
            }
        )

    return {
        "total": len(normalized),
        "successful": sum(
            1
            for item in normalized
            if item["success"]
        ),
        "failed": sum(
            1
            for item in normalized
            if not item["success"]
        ),
        "items": normalized,
    }


def build_dashboard_summary(
    findings,
    overall_risk,
    secrets=None,
    dependencies=None,
    fixes=None,
):
    """
    Build the high-level dashboard cards.
    """

    findings = _list(findings)
    overall_risk = _dict(
        overall_risk
    )

    secrets = normalize_secret_report(
        secrets
    )

    dependencies = normalize_dependency_report(
        dependencies
    )

    fixes = normalize_autofix_report(
        fixes
    )

    severity_counts = _dict(
        overall_risk.get(
            "severity_counts"
        )
    )

    return {
        "total_findings": len(
            findings
        ),
        "critical": severity_counts.get(
            "CRITICAL",
            0,
        ),
        "high": severity_counts.get(
            "HIGH",
            0,
        ),
        "medium": severity_counts.get(
            "MEDIUM",
            0,
        ),
        "low": severity_counts.get(
            "LOW",
            0,
        ),
        "info": severity_counts.get(
            "INFO",
            0,
        ),
        "secrets": secrets["count"],
        "dependency_vulnerabilities": (
            dependencies["count"]
        ),
        "ai_fixes_generated": (
            fixes["successful"]
        ),
        "ai_fixes_failed": (
            fixes["failed"]
        ),
        "overall_risk_score": _value(
            overall_risk,
            [
                "score",
                "overall_score",
            ],
            0,
        ),
        "overall_risk_level": _value(
            overall_risk,
            [
                "risk_level",
                "level",
            ],
            "Secure",
        ),
    }