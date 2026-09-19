"""
SentinelForge AI - Report Response Schemas

Schemas for dependency findings, secret findings,
Auto-Fix information and dashboard/report summaries.

These schemas describe output data only.
They do not perform scanning or security decisions.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SecretFinding(BaseModel):
    secret_id: str = ""
    type: str = "Potential Secret"
    file: str = "Unknown"
    line: int | str = "Unknown"
    masked_value: str = ""
    message: str = ""
    severity: str = "HIGH"


class SecretReport(BaseModel):
    count: int = 0
    findings: list[SecretFinding] = Field(
        default_factory=list
    )


class DependencyVulnerability(BaseModel):
    dependency_id: str = ""
    package: str = "Unknown"
    ecosystem: str = "Unknown"
    version: str = "Unknown"
    vulnerability_id: str = "Unknown"
    aliases: list[str] = Field(
        default_factory=list
    )
    severity: str = "Unknown"
    summary: str = ""
    fixed_version: str = ""
    source_file: str = "Unknown"


class DependencyReport(BaseModel):
    count: int = 0
    vulnerabilities: list[
        DependencyVulnerability
    ] = Field(
        default_factory=list
    )
    dependency_files: list[str] = Field(
        default_factory=list
    )


class AutoFixDisplay(BaseModel):
    finding_id: str = ""
    success: bool = False
    status: str = "Failed"
    file: str = "Unknown"
    original_code: str = ""
    fixed_code: str = ""
    validation: dict[str, Any] = Field(
        default_factory=dict
    )


class AutoFixReport(BaseModel):
    total: int = 0
    successful: int = 0
    failed: int = 0
    items: list[AutoFixDisplay] = Field(
        default_factory=list
    )


class DashboardSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    secrets: int = 0
    dependency_vulnerabilities: int = 0

    ai_fixes_generated: int = 0
    ai_fixes_failed: int = 0

    overall_risk_score: float | int = 0
    overall_risk_level: str = "Secure"


class SecurityReportData(BaseModel):
    repository: str = ""

    summary: DashboardSummary = Field(
        default_factory=DashboardSummary
    )

    findings: list[dict[str, Any]] = Field(
        default_factory=list
    )

    auto_fix: AutoFixReport = Field(
        default_factory=AutoFixReport
    )

    duplicate_similarity: list[
        dict[str, Any]
    ] = Field(
        default_factory=list
    )

    secrets: SecretReport = Field(
        default_factory=SecretReport
    )

    dependencies: DependencyReport = Field(
        default_factory=DependencyReport
    )