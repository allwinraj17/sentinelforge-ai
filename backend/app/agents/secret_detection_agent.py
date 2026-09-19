"""
SentinelForge AI - Secret Detection Agent

Detects potentially exposed secrets in source-code repositories.

The agent:
- scans common source/configuration files
- detects common API keys, tokens, passwords and credentials
- detects private keys
- detects JWTs
- detects AWS credentials
- detects database connection credentials
- masks secret values before returning results

Important:
Actual secret values are NEVER returned in the finding.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_FILE_SIZE = 5 * 1024 * 1024

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".next",
    ".idea",
    ".vscode",
}

IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}


# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "AWS Access Key",
        "type": "AWS Credential",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
    },
    {
        "name": "AWS Temporary Access Key",
        "type": "AWS Credential",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"\bASIA[0-9A-Z]{16}\b"
        ),
    },
    {
        "name": "AWS Secret Access Key",
        "type": "AWS Secret",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?i)(?:aws_secret_access_key|"
            r"aws_secret|secret_access_key)"
            r"\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9/+=]{30,})"
        ),
        "capture_group": 1,
    },
    {
        "name": "GitHub Personal Access Token",
        "type": "GitHub Token",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"\bghp_[A-Za-z0-9]{36}\b"
        ),
    },
    {
        "name": "GitHub OAuth Token",
        "type": "GitHub Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bgho_[A-Za-z0-9]{36}\b"
        ),
    },
    {
        "name": "GitHub App Token",
        "type": "GitHub Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bghs_[A-Za-z0-9]{36}\b"
        ),
    },
    {
        "name": "Google API Key",
        "type": "Google API Key",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bAIza[0-9A-Za-z\-_]{35}\b"
        ),
    },
    {
        "name": "Slack Token",
        "type": "Slack Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"
        ),
    },
    {
        "name": "Private Key",
        "type": "Private Key",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |DSA |OPENSSH |PGP )?"
            r"PRIVATE KEY-----"
        ),
    },
    {
        "name": "JWT Token",
        "type": "JWT",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\beyJ[A-Za-z0-9_-]{5,}"
            r"\."
            r"[A-Za-z0-9_-]{5,}"
            r"\."
            r"[A-Za-z0-9_-]{5,}\b"
        ),
    },
    {
        "name": "Bearer Token",
        "type": "Authorization Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)\bBearer\s+"
            r"([A-Za-z0-9._~+/=-]{20,})"
        ),
        "capture_group": 1,
    },
    {
        "name": "Authorization Token",
        "type": "Authorization Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)(?:authorization|auth_token|"
            r"access_token|refresh_token)"
            r"\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9._~+/=-]{20,})"
        ),
        "capture_group": 1,
    },
    {
        "name": "API Key",
        "type": "API Key",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)(?:api[_-]?key|apikey)"
            r"\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9_\-]{20,})"
        ),
        "capture_group": 1,
    },
    {
        "name": "API Secret",
        "type": "API Secret",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)(?:api[_-]?secret|client[_-]?secret)"
            r"\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9_\-]{16,})"
        ),
        "capture_group": 1,
    },
    {
        "name": "Database Password",
        "type": "Database Credential",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?i)(?:db[_-]?password|database[_-]?password|"
            r"db[_-]?pass|database[_-]?pass)"
            r"\s*[:=]\s*['\"]?"
            r"([^'\"\s;,]{6,})"
        ),
        "capture_group": 1,
    },
    {
        "name": "Password Assignment",
        "type": "Password",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?i)(?:password|passwd|pwd)"
            r"\s*[:=]\s*['\"]?"
            r"([^'\"\s;,]{8,})"
        ),
        "capture_group": 1,
    },
    {
        "name": "Database Connection String",
        "type": "Database Credential",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?i)\b(?:mongodb|mongodb\+srv|"
            r"mysql|postgresql|postgres|"
            r"mssql|redis)://"
            r"[^:\s/@]+:"
            r"[^@\s]+@"
        ),
    },
    {
        "name": "Private Database URL",
        "type": "Database Credential",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?i)\b(?:jdbc:"
            r"(?:mysql|postgresql|postgres|sqlserver):"
            r"//[^:\s]+:[^@\s]+@)"
        ),
    },
]


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _is_ignored(path: Path) -> bool:
    """Return True when a file should not be scanned."""

    if path.name in IGNORED_FILES:
        return True

    return any(
        part in IGNORED_DIRECTORIES
        for part in path.parts
    )


def _read_file(path: Path) -> str:
    """Read a text file safely."""

    try:
        if not path.is_file():
            return ""

        if path.stat().st_size > MAX_FILE_SIZE:
            return ""

        return path.read_text(
            encoding="utf-8",
            errors="ignore",
        )

    except Exception:
        return ""


def _mask_secret(secret: str) -> str:
    """
    Mask a detected secret.

    Only a small prefix/suffix is retained for identification.
    """

    if not secret:
        return "[REDACTED]"

    secret = str(secret)

    if len(secret) <= 8:
        return "[REDACTED]"

    if len(secret) <= 14:
        return (
            secret[:3]
            + "****"
            + secret[-2:]
        )

    return (
        secret[:4]
        + "****"
        + secret[-4:]
    )


def _extract_secret(
    match: re.Match[str],
    pattern_definition: dict[str, Any],
) -> str:
    """Extract the actual matched secret before masking."""

    capture_group = pattern_definition.get(
        "capture_group"
    )

    if capture_group:
        try:
            value = match.group(capture_group)

            if value:
                return value

        except (IndexError, AttributeError):
            pass

    return match.group(0)


# ---------------------------------------------------------------------------
# Finding creation
# ---------------------------------------------------------------------------

def _create_finding(
    pattern_definition: dict[str, Any],
    path: Path,
    line_number: int,
    line_text: str,
    match: re.Match[str],
) -> dict[str, Any]:
    """Create a safe secret finding."""

    secret_value = _extract_secret(
        match,
        pattern_definition,
    )

    masked_value = _mask_secret(
        secret_value
    )

    return {
        "type": "Secret",
        "secret_type": pattern_definition["type"],
        "name": pattern_definition["name"],
        "severity": pattern_definition["severity"],
        "file": str(path),
        "line": line_number,
        "message": (
            f"Potential {pattern_definition['name']} "
            f"detected."
        ),
        "description": (
            "A potentially exposed credential, token, "
            "key, password, or private key was detected."
        ),
        "masked_value": masked_value,
        "secret_exposed": True,
        "recommendation": (
            "Remove the secret from source code, rotate "
            "the exposed credential, and store secrets "
            "using environment variables or a secure "
            "secret-management system."
        ),
        "scanner": "SentinelForge Secret Detection Agent",
        "raw_line": _mask_line(
            line_text,
            secret_value,
            masked_value,
        ),
    }


def _mask_line(
    line_text: str,
    secret_value: str,
    masked_value: str,
) -> str:
    """Return the source line with the detected secret masked."""

    if not line_text:
        return ""

    if secret_value:
        try:
            return line_text.replace(
                secret_value,
                masked_value,
            )
        except Exception:
            pass

    return line_text[:500]


# ---------------------------------------------------------------------------
# Main scanning logic
# ---------------------------------------------------------------------------

def _scan_file(
    path: Path,
) -> list[dict[str, Any]]:
    """Scan one file for secret patterns."""

    content = _read_file(path)

    if not content:
        return []

    findings: list[dict[str, Any]] = []

    lines = content.splitlines()

    for line_number, line_text in enumerate(
        lines,
        start=1,
    ):
        for pattern_definition in SECRET_PATTERNS:
            pattern = pattern_definition["pattern"]

            try:
                matches = pattern.finditer(
                    line_text
                )

                for match in matches:
                    finding = _create_finding(
                        pattern_definition,
                        path,
                        line_number,
                        line_text,
                        match,
                    )

                    findings.append(finding)

            except Exception:
                continue

    return findings


def _deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove duplicate findings."""

    unique: dict[
        tuple[str, int, str, str],
        dict[str, Any],
    ] = {}

    for finding in findings:
        key = (
            str(finding.get("file")),
            int(finding.get("line", 0)),
            str(finding.get("secret_type")),
            str(finding.get("masked_value")),
        )

        unique[key] = finding

    return list(unique.values())


# ---------------------------------------------------------------------------
# Public agent function
# ---------------------------------------------------------------------------

def run_secret_detection(
    repository_path: str | Path,
) -> dict[str, Any]:
    """
    Scan a repository for exposed secrets.

    Parameters
    ----------
    repository_path:
        Root directory of the extracted repository.

    Returns
    -------
    dict
        Structured secret detection results.
    """

    root = Path(repository_path)

    if not root.exists() or not root.is_dir():
        return {
            "agent": "secret_detection_agent",
            "status": "error",
            "message": (
                "Repository directory does not exist."
            ),
            "findings": [],
            "total_secrets": 0,
            "critical_secrets": 0,
            "high_secrets": 0,
        }

    findings: list[dict[str, Any]] = []

    files_scanned = 0

    try:
        for path in root.rglob("*"):
            if not path.is_file():
                continue

            if _is_ignored(path):
                continue

            # Skip very large files before reading.
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            files_scanned += 1

            findings.extend(
                _scan_file(path)
            )

        findings = _deduplicate_findings(
            findings
        )

        # Sort findings consistently.
        findings.sort(
            key=lambda finding: (
                str(finding.get("file", "")),
                int(finding.get("line", 0)),
                str(finding.get("secret_type", "")),
            )
        )

        critical_count = sum(
            1
            for finding in findings
            if finding.get("severity") == "CRITICAL"
        )

        high_count = sum(
            1
            for finding in findings
            if finding.get("severity") == "HIGH"
        )

        return {
            "agent": "secret_detection_agent",
            "status": "completed",
            "message": (
                "Secret detection completed."
            ),
            "findings": findings,
            "total_secrets": len(findings),
            "critical_secrets": critical_count,
            "high_secrets": high_count,
            "files_scanned": files_scanned,
        }

    except Exception as exc:
        return {
            "agent": "secret_detection_agent",
            "status": "error",
            "message": (
                f"Secret detection failed: {exc}"
            ),
            "findings": findings,
            "total_secrets": len(findings),
            "critical_secrets": 0,
            "high_secrets": 0,
            "files_scanned": files_scanned,
        }