from __future__ import annotations

from typing import Any


# ============================================================
# VALIDATE ONE FIX ARTIFACT
# ============================================================

def validate_fix_artifact(
    fix: dict[str, Any],
) -> dict[str, Any]:
    """
    Perform lightweight validation of one AI-generated fix.

    This checks only whether the remediation artifact is
    structurally available.

    It does NOT perform security verification.
    """

    if not isinstance(
        fix,
        dict,
    ):
        return {
            "success": False,
            "status": "attention",
            "message": (
                "Invalid remediation artifact."
            ),
            "security_scan_performed": False,
            "affects_security_findings": False,
        }


    original_path = fix.get(
        "original_path",
        "",
    )

    fixed_code = fix.get(
        "fixed_code",
        None,
    )

    fix_success = bool(
        fix.get(
            "success",
            False,
        )
    )


    # ========================================================
    # BASIC ARTIFACT CHECK
    # ========================================================

    if not fix_success:

        return {
            "success": False,
            "status": "attention",
            "message": (
                "No successful AI-generated fix "
                "is available for this finding."
            ),
            "path": original_path,
            "security_scan_performed": False,
            "affects_security_findings": False,
        }


    if not original_path:

        return {
            "success": False,
            "status": "attention",
            "message": (
                "Fix artifact does not contain "
                "an original file path."
            ),
            "security_scan_performed": False,
            "affects_security_findings": False,
        }


    if not isinstance(
        fixed_code,
        str,
    ):

        return {
            "success": False,
            "status": "attention",
            "message": (
                "Generated fix content is not valid text."
            ),
            "path": original_path,
            "security_scan_performed": False,
            "affects_security_findings": False,
        }


    if not fixed_code.strip():

        return {
            "success": False,
            "status": "attention",
            "message": (
                "Generated fix content is empty."
            ),
            "path": original_path,
            "security_scan_performed": False,
            "affects_security_findings": False,
        }


    # ========================================================
    # VALIDATION PREPARATION SUCCESS
    # ========================================================

    return {
        "success": True,
        "status": "ready",
        "message": (
            "Generated remediation artifact is "
            "available for final output preparation."
        ),
        "path": original_path,
        "content_available": True,

        # IMPORTANT:
        # These explicitly document that this agent is NOT
        # performing a second security scan.
        "security_scan_performed": False,
        "second_semgrep_scan": False,

        # The validation result must never modify the original
        # security findings or risk calculations.
        "affects_security_findings": False,
        "affects_risk_score": False,
    }


# ============================================================
# VALIDATE ALL FIX ARTIFACTS
# ============================================================

def run_validation_agent(
    fixes: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Run lightweight validation preparation for all
    generated remediation artifacts.

    The output is informational only.

    It does NOT modify the original findings,
    risk assessments or overall risk.
    """

    if not isinstance(
        fixes,
        list,
    ):
        fixes = []


    results = []

    for fix in fixes:

        results.append(
            validate_fix_artifact(
                fix
            )
        )


    ready_count = sum(
        1
        for result in results
        if result.get(
            "success",
            False,
        )
    )


    attention_count = (
        len(results)
        - ready_count
    )


    return {
        "success": True,

        "status": "completed",

        "message": (
            "Validation Agent completed lightweight "
            "remediation artifact checks."
        ),

        "results": results,

        "total_artifacts": len(results),

        "ready_artifacts": ready_count,

        "attention_artifacts": attention_count,

        # Explicit architecture information.
        "security_scan_performed": False,

        "second_semgrep_scan": False,

        "findings_modified": False,

        "risk_modified": False,

        "security_verified": False,
    }