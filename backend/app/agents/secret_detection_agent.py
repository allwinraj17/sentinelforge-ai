from __future__ import annotations

import re

from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".vite",
    "coverage",
}


IGNORED_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
}


TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".go",
    ".rs",
    ".php",
    ".rb",
    ".dart",
    ".kt",
    ".swift",
    ".html",
    ".css",
    ".sql",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".properties",
    ".env",
    ".txt",
    ".ini",
    ".conf",
}


SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
        "severity": "high",
        "cwe": "CWE-798",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(
            r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"
        ),
        "severity": "high",
        "cwe": "CWE-798",
    },
    {
        "name": "Bearer Token",
        "pattern": re.compile(
            r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"
        ),
        "severity": "high",
        "cwe": "CWE-798",
    },
    {
        "name": "Private Key",
        "pattern": re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH )?"
            r"PRIVATE KEY-----"
        ),
        "severity": "critical",
        "cwe": "CWE-321",
    },
    {
        "name": "API Key",
        "pattern": re.compile(
            r"(?i)\bapi[_\- ]?key\s*[:=]\s*['\"]?"
            r"[A-Za-z0-9_\-]{12,}"
        ),
        "severity": "high",
        "cwe": "CWE-798",
    },
    {
        "name": "Secret",
        "pattern": re.compile(
            r"(?i)\bsecret\s*[:=]\s*['\"]?"
            r"[A-Za-z0-9_\-]{8,}"
        ),
        "severity": "high",
        "cwe": "CWE-798",
    },
    {
        "name": "Password Assignment",
        "pattern": re.compile(
            r"(?i)\bpassword\s*[:=]\s*['\"]?"
            r"[^'\"\s]{6,}"
        ),
        "severity": "high",
        "cwe": "CWE-798",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}"
            r"\.[A-Za-z0-9_-]{10,}"
            r"\.[A-Za-z0-9_-]{10,}\b"
        ),
        "severity": "high",
        "cwe": "CWE-798",
    },
]


def should_ignore(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORED_DIRECTORIES:
            return True

    if path.name in IGNORED_FILES:
        return True

    return False


def is_text_file(path: Path) -> bool:
    return (
        path.suffix.lower() in TEXT_EXTENSIONS
        or path.name.lower() in {
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
        }
    )


def mask_secret(value: str) -> str:
    value = str(value)

    if len(value) <= 8:
        return "*" * len(value)

    return (
        value[:4]
        + "*" * (len(value) - 8)
        + value[-4:]
    )


def create_finding(
    repository_relative_path: str,
    line_number: int,
    secret_type: str,
    secret_value: str,
    severity: str,
    cwe: str,
) -> dict[str, Any]:

    return {
        "check_id": (
            "secret-detection."
            + secret_type.lower().replace(
                " ",
                "-",
            )
        ),
        "path": repository_relative_path,
        "start": {
            "line": line_number,
            "col": 1,
        },
        "end": {
            "line": line_number,
            "col": 1,
        },
        "extra": {
            "message": (
                f"Potential {secret_type} detected."
            ),
            "severity": severity,
            "metadata": {
                "severity": severity,
                "cwe": cwe,
                "secret_type": secret_type,
                "source": (
                    "Secret Detection Agent"
                ),
            },
            "secret_value": mask_secret(
                secret_value
            ),
        },
    }


def run_secret_detection(
    repository_path: str | Path,
) -> dict[str, Any]:
    """
    Secret Detection Agent.

    Scans text-based repository files for common
    credential and secret patterns.

    Secret values are masked in the returned result.
    """

    root = Path(repository_path).resolve()

    if not root.exists():
        return {
            "agent": "Secret Detection Agent",
            "success": False,
            "findings_count": 0,
            "findings": [],
            "error": (
                "Repository path does not exist."
            ),
        }

    findings = []

    for path in root.rglob("*"):
        if should_ignore(path):
            continue

        if not path.is_file():
            continue

        if not is_text_file(path):
            continue

        try:
            content = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            continue

        lines = content.splitlines()

        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            for secret_rule in SECRET_PATTERNS:
                matches = secret_rule[
                    "pattern"
                ].finditer(line)

                for match in matches:
                    try:
                        relative_path = (
                            path.relative_to(root)
                            .as_posix()
                        )
                    except ValueError:
                        continue

                    finding = create_finding(
                        repository_relative_path=(
                            relative_path
                        ),
                        line_number=line_number,
                        secret_type=(
                            secret_rule["name"]
                        ),
                        secret_value=match.group(
                            0
                        ),
                        severity=(
                            secret_rule["severity"]
                        ),
                        cwe=secret_rule["cwe"],
                    )

                    findings.append(finding)

    return {
        "agent": "Secret Detection Agent",
        "success": True,
        "findings_count": len(findings),
        "findings": findings,
    }