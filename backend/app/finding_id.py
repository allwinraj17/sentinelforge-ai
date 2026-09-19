"""
Finding ID utilities for SentinelForge AI.

This module provides a small, centralized mechanism for assigning
and validating unique finding IDs.

Finding IDs are used to connect the same security finding across
the different stages of the security analysis pipeline:

    Detection
        ↓
    ML Intelligence
        ↓
    Risk Assessment
        ↓
    AI Auto-Fix
        ↓
    Validation
        ↓
    Dashboard / Report

Example IDs:

    F001
    F002
    F003
"""

from __future__ import annotations

import re
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================

FINDING_ID_PATTERN = re.compile(
    r"^F\d{3,}$"
)


# ============================================================
# FINDING ID GENERATION
# ============================================================

def make_finding_id(
    index: int,
) -> str:
    """
    Create a formatted finding ID.

    Examples:

        1  -> F001
        2  -> F002
        9  -> F009
        10 -> F010
        100 -> F100
        1000 -> F1000

    Args:
        index:
            Positive integer used for the finding number.

    Returns:
        A formatted finding ID.

    Raises:
        ValueError:
            If index is less than 1.
    """

    try:
        numeric_index = int(index)

    except (
        TypeError,
        ValueError,
    ) as exc:

        raise ValueError(
            "Finding ID index must be an integer."
        ) from exc

    if numeric_index < 1:
        raise ValueError(
            "Finding ID index must be greater than zero."
        )

    return f"F{numeric_index:03d}"


# ============================================================
# FINDING ID VALIDATION
# ============================================================

def is_valid_finding_id(
    finding_id: Any,
) -> bool:
    """
    Check whether a value is a valid SentinelForge finding ID.

    Valid examples:

        F001
        F002
        F100
        F1000

    Invalid examples:

        finding-1
        001
        f001
        F-001
        vulnerability-1
        None
    """

    if finding_id is None:
        return False

    value = str(
        finding_id
    ).strip()

    return bool(
        FINDING_ID_PATTERN.fullmatch(
            value
        )
    )


# ============================================================
# GET FINDING ID
# ============================================================

def get_finding_id(
    finding: dict[str, Any],
) -> str | None:
    """
    Safely retrieve a finding ID from a finding dictionary.

    The canonical field is:

        finding_id

    A small amount of backward compatibility is supported for
    existing data that may use:

        id
        findingId

    The canonical returned value is always a string.
    """

    if not isinstance(
        finding,
        dict,
    ):
        return None

    candidates = [
        finding.get(
            "finding_id"
        ),
        finding.get(
            "id"
        ),
        finding.get(
            "findingId"
        ),
    ]

    for candidate in candidates:

        if candidate is None:
            continue

        value = str(
            candidate
        ).strip()

        if not value:
            continue

        if is_valid_finding_id(
            value
        ):
            return value

    return None


# ============================================================
# ASSIGN ONE FINDING ID
# ============================================================

def assign_finding_id(
    finding: dict[str, Any],
    index: int,
) -> str:
    """
    Assign a finding ID to one finding.

    Existing valid finding IDs are preserved.

    This is important because later pipeline stages should not
    accidentally replace an ID that was already assigned.

    Args:
        finding:
            Finding dictionary to update.

        index:
            Numeric index used when the finding does not already
            have a valid ID.

    Returns:
        The finding ID assigned to the finding.

    Raises:
        TypeError:
            If finding is not a dictionary.
    """

    if not isinstance(
        finding,
        dict,
    ):
        raise TypeError(
            "Finding must be a dictionary."
        )

    existing_id = get_finding_id(
        finding
    )

    if existing_id:
        finding[
            "finding_id"
        ] = existing_id

        return existing_id

    finding_id = make_finding_id(
        index
    )

    finding[
        "finding_id"
    ] = finding_id

    return finding_id


# ============================================================
# ASSIGN IDS TO FINDINGS
# ============================================================

def assign_finding_ids(
    findings: list[dict[str, Any]],
    start_index: int = 1,
) -> list[dict[str, Any]]:
    """
    Assign unique finding IDs to a list of findings.

    Existing valid IDs are preserved.

    New IDs are assigned sequentially.

    Example:

        findings = [
            {...},
            {...},
            {...},
        ]

    becomes:

        [
            {"finding_id": "F001", ...},
            {"finding_id": "F002", ...},
            {"finding_id": "F003", ...},
        ]

    Args:
        findings:
            List of finding dictionaries.

        start_index:
            First numeric ID to use.

    Returns:
        The same findings list with finding IDs assigned.

    Raises:
        ValueError:
            If start_index is less than 1.
    """

    if not isinstance(
        findings,
        list,
    ):
        return []

    try:
        current_index = int(
            start_index
        )

    except (
        TypeError,
        ValueError,
    ) as exc:

        raise ValueError(
            "start_index must be an integer."
        ) from exc

    if current_index < 1:
        raise ValueError(
            "start_index must be greater than zero."
        )

    used_ids: set[str] = set()

    # --------------------------------------------------------
    # Preserve existing valid IDs first.
    # --------------------------------------------------------

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        existing_id = get_finding_id(
            finding
        )

        if existing_id:
            finding[
                "finding_id"
            ] = existing_id

            used_ids.add(
                existing_id
            )

    # --------------------------------------------------------
    # Assign new IDs.
    # --------------------------------------------------------

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        existing_id = get_finding_id(
            finding
        )

        if existing_id:
            continue

        while True:

            candidate = make_finding_id(
                current_index
            )

            current_index += 1

            if candidate not in used_ids:
                break

        finding[
            "finding_id"
        ] = candidate

        used_ids.add(
            candidate
        )

    return findings


# ============================================================
# FINDING ID MAP
# ============================================================

def build_finding_id_map(
    findings: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Build a lookup dictionary using finding IDs.

    Example:

        {
            "F001": {...},
            "F002": {...},
            "F003": {...}
        }

    This is useful when later pipeline stages need to quickly
    locate the complete finding associated with an ID.
    """

    result: dict[
        str,
        dict[str, Any]
    ] = {}

    if not isinstance(
        findings,
        list,
    ):
        return result

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        finding_id = get_finding_id(
            finding
        )

        if not finding_id:
            continue

        result[
            finding_id
        ] = finding

    return result


# ============================================================
# FINDING ID LIST
# ============================================================

def get_finding_ids(
    findings: list[dict[str, Any]],
) -> list[str]:
    """
    Return all valid finding IDs from a list of findings.

    The order is preserved.
    """

    result: list[str] = []

    if not isinstance(
        findings,
        list,
    ):
        return result

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        finding_id = get_finding_id(
            finding
        )

        if finding_id:
            result.append(
                finding_id
            )

    return result


# ============================================================
# FINDING ID SUMMARY
# ============================================================

def summarize_finding_ids(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Return a small summary of finding ID information.

    This is useful for debugging and API responses.
    """

    ids = get_finding_ids(
        findings
    )

    return {
        "total_findings": len(
            findings
        )
        if isinstance(
            findings,
            list,
        )
        else 0,

        "findings_with_ids": len(
            ids
        ),

        "finding_ids": ids,

        "ids_are_unique": (
            len(ids)
            == len(set(ids))
        ),
    }