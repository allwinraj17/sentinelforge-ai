from __future__ import annotations

from typing import Any


CWE_TO_OWASP = {
    "CWE-79": {
        "category": "A03",
        "title": "Injection",
    },
    "CWE-89": {
        "category": "A03",
        "title": "Injection",
    },
    "CWE-78": {
        "category": "A03",
        "title": "Injection",
    },
    "CWE-94": {
        "category": "A03",
        "title": "Injection",
    },
    "CWE-22": {
        "category": "A01",
        "title": "Broken Access Control",
    },
    "CWE-200": {
        "category": "A01",
        "title": "Broken Access Control",
    },
    "CWE-287": {
        "category": "A07",
        "title": (
            "Identification and Authentication "
            "Failures"
        ),
    },
    "CWE-306": {
        "category": "A07",
        "title": (
            "Identification and Authentication "
            "Failures"
        ),
    },
    "CWE-798": {
        "category": "A07",
        "title": (
            "Identification and Authentication "
            "Failures"
        ),
    },
    "CWE-321": {
        "category": "A02",
        "title": "Cryptographic Failures",
    },
    "CWE-327": {
        "category": "A02",
        "title": "Cryptographic Failures",
    },
    "CWE-328": {
        "category": "A02",
        "title": "Cryptographic Failures",
    },
    "CWE-502": {
        "category": "A08",
        "title": (
            "Software and Data Integrity Failures"
        ),
    },
    "CWE-611": {
        "category": "A05",
        "title": "Security Misconfiguration",
    },
    "CWE-16": {
        "category": "A05",
        "title": "Security Misconfiguration",
    },
    "CWE-209": {
        "category": "A05",
        "title": "Security Misconfiguration",
    },
    "CWE-918": {
        "category": "A10",
        "title": "Server-Side Request Forgery",
    },
}


def extract_cwe(
    finding: dict[str, Any],
) -> str | None:

    extra = finding.get(
        "extra",
        {},
    )

    if not isinstance(extra, dict):
        return None

    metadata = extra.get(
        "metadata",
        {},
    )

    if not isinstance(metadata, dict):
        return None

    cwe = metadata.get(
        "cwe"
    )

    if isinstance(cwe, list):
        if cwe:
            return str(cwe[0])

    if cwe:
        return str(cwe)

    return None


def finding_text(
    finding: dict[str, Any],
) -> str:

    values = []

    check_id = finding.get(
        "check_id",
        "",
    )

    values.append(
        str(check_id)
    )

    extra = finding.get(
        "extra",
        {},
    )

    if isinstance(extra, dict):
        values.append(
            str(
                extra.get(
                    "message",
                    "",
                )
            )
        )

    return " ".join(values).lower()


def fallback_mapping(
    finding: dict[str, Any],
) -> dict[str, str] | None:

    text = finding_text(
        finding
    )

    if (
        "sql injection" in text
        or "command injection" in text
        or "code injection" in text
        or "xss" in text
    ):
        return {
            "category": "A03",
            "title": "Injection",
        }

    if (
        "secret" in text
        or "password" in text
        or "credential" in text
        or "token" in text
    ):
        return {
            "category": "A07",
            "title": (
                "Identification and "
                "Authentication Failures"
            ),
        }

    if (
        "misconfiguration" in text
        or "debug" in text
    ):
        return {
            "category": "A05",
            "title": "Security Misconfiguration",
        }

    return None


def run_compliance_agent(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Compliance Agent.

    Maps security findings to relevant
    OWASP Top 10 2021 categories.

    This is supportive compliance mapping,
    not a formal compliance certification.
    """

    if not isinstance(
        findings,
        list,
    ):
        findings = []

    mappings = []

    for index, finding in enumerate(
        findings
    ):
        if not isinstance(
            finding,
            dict,
        ):
            continue

        cwe = extract_cwe(
            finding
        )

        mapping = None

        if cwe:
            mapping = CWE_TO_OWASP.get(
                cwe
            )

        if mapping is None:
            mapping = fallback_mapping(
                finding
            )

        if mapping is None:
            mapping = {
                "category": "Unmapped",
                "title": (
                    "No direct OWASP mapping"
                ),
            }

        mappings.append(
            {
                "finding_index": index,
                "check_id": finding.get(
                    "check_id",
                    "unknown",
                ),
                "path": finding.get(
                    "path",
                    "",
                ),
                "cwe": cwe,
                "owasp_category": (
                    mapping["category"]
                ),
                "owasp_title": (
                    mapping["title"]
                ),
            }
        )

    category_counts: dict[str, int] = {}

    for item in mappings:
        category = item[
            "owasp_category"
        ]

        category_counts[category] = (
            category_counts.get(
                category,
                0,
            )
            + 1
        )

    return {
        "agent": "Compliance Agent",
        "success": True,
        "framework": "OWASP Top 10 2021",
        "findings_mapped": len(mappings),
        "mappings": mappings,
        "category_counts": category_counts,
        "note": (
            "OWASP mapping is provided as a "
            "supportive security classification "
            "and does not constitute formal "
            "compliance certification."
        ),
    }