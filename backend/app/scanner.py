import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_EXTRACTED_FILES = 5000
MAX_SINGLE_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
SEMGREP_TIMEOUT = 300


# ============================================================
# SEMGREP SCANNER
# ============================================================

def run_semgrep_scan(target_dir: str) -> list[dict]:
    """
    Run Semgrep against the extracted repository.

    Returns:
        A list of Semgrep findings.

    Raises:
        RuntimeError if Semgrep cannot run or returns invalid output.
    """

    target_path = Path(target_dir)

    if not target_path.exists():
        raise RuntimeError("Scan directory does not exist.")

    if not target_path.is_dir():
        raise RuntimeError("Scan target is not a directory.")

    # --------------------------------------------------------
    # Check that Semgrep is installed
    # --------------------------------------------------------

    semgrep_path = shutil.which("semgrep")

    if not semgrep_path:
        raise RuntimeError(
            "Semgrep is not installed or is not available in PATH."
        )

    # --------------------------------------------------------
    # Run Semgrep
    # --------------------------------------------------------

    command = [
        semgrep_path,
        "--config=auto",
        "--json",
        "--no-git-ignore",
        str(target_path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT,
            encoding="utf-8",
            errors="replace",
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Semgrep scan exceeded the {SEMGREP_TIMEOUT} second timeout."
        )

    except OSError as exc:
        raise RuntimeError(
            f"Unable to start Semgrep: {exc}"
        )

    # --------------------------------------------------------
    # Semgrep return codes
    #
    # 0 = scan completed without findings
    # 1 = scan completed with findings
    # --------------------------------------------------------

    if result.returncode not in (0, 1):
        stderr = result.stderr.strip()

        if not stderr:
            stderr = "Unknown Semgrep error."

        raise RuntimeError(
            f"Semgrep failed with exit code "
            f"{result.returncode}: {stderr}"
        )

    # --------------------------------------------------------
    # Parse JSON
    # --------------------------------------------------------

    stdout = result.stdout.strip()

    if not stdout:
        return []

    try:
        data = json.loads(stdout)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Semgrep returned invalid JSON: {exc}"
        )

    # --------------------------------------------------------
    # Extract findings
    # --------------------------------------------------------

    findings = data.get("results", [])

    if not isinstance(findings, list):
        raise RuntimeError(
            "Semgrep returned an unexpected results format."
        )

    return findings


# ============================================================
# ZIP SECURITY VALIDATION
# ============================================================

def _validate_zip_file(
    zip_file: zipfile.ZipFile,
) -> None:
    """
    Validate ZIP contents before extraction.

    Protects against:
    - Path traversal / Zip Slip
    - Excessive number of files
    - Extremely large files
    """

    members = zip_file.infolist()

    if len(members) > MAX_EXTRACTED_FILES:
        raise ValueError(
            f"ZIP contains too many files. "
            f"Maximum allowed is {MAX_EXTRACTED_FILES}."
        )

    total_size = 0

    for member in members:

        filename = member.filename

        # ----------------------------------------------------
        # Ignore directory entries
        # ----------------------------------------------------

        if not filename:
            continue

        # ----------------------------------------------------
        # Prevent absolute paths
        # ----------------------------------------------------

        path = Path(filename)

        if path.is_absolute():
            raise ValueError(
                f"Unsafe ZIP entry detected: {filename}"
            )

        # ----------------------------------------------------
        # Prevent Windows absolute paths
        # ----------------------------------------------------

        normalized = filename.replace("\\", "/")

        if normalized.startswith("/"):
            raise ValueError(
                f"Unsafe ZIP entry detected: {filename}"
            )

        # ----------------------------------------------------
        # Prevent ../ traversal
        # ----------------------------------------------------

        parts = Path(normalized).parts

        if ".." in parts:
            raise ValueError(
                f"Unsafe ZIP entry detected: {filename}"
            )

        # ----------------------------------------------------
        # Check file size
        # ----------------------------------------------------

        if not member.is_dir():

            if member.file_size > MAX_SINGLE_FILE_SIZE:
                raise ValueError(
                    f"File '{filename}' is too large. "
                    f"Maximum allowed size is "
                    f"{MAX_SINGLE_FILE_SIZE // (1024 * 1024)} MB."
                )

            total_size += member.file_size

    # --------------------------------------------------------
    # Prevent decompression bomb style archives
    # --------------------------------------------------------

    if total_size > MAX_ZIP_SIZE:
        raise ValueError(
            f"Extracted ZIP content is too large. "
            f"Maximum allowed size is "
            f"{MAX_ZIP_SIZE // (1024 * 1024)} MB."
        )


# ============================================================
# SAFE ZIP EXTRACTION
# ============================================================

def extract_zip_to_temp(zip_bytes: bytes) -> str:
    """
    Save uploaded ZIP data into a temporary directory,
    validate it, and safely extract it.

    Returns:
        Path to extracted repository directory.
    """

    if not zip_bytes:
        raise ValueError("The uploaded ZIP file is empty.")

    # --------------------------------------------------------
    # Check uploaded ZIP size
    # --------------------------------------------------------

    if len(zip_bytes) > MAX_ZIP_SIZE:
        raise ValueError(
            f"ZIP file is too large. "
            f"Maximum upload size is "
            f"{MAX_ZIP_SIZE // (1024 * 1024)} MB."
        )

    # --------------------------------------------------------
    # Create temporary directory
    # --------------------------------------------------------

    temp_dir = tempfile.mkdtemp(
        prefix="sentinelforge_"
    )

    zip_path = os.path.join(
        temp_dir,
        "upload.zip",
    )

    extract_dir = os.path.join(
        temp_dir,
        "extracted",
    )

    try:

        # ----------------------------------------------------
        # Save ZIP
        # ----------------------------------------------------

        with open(zip_path, "wb") as file:
            file.write(zip_bytes)

        # ----------------------------------------------------
        # Open and validate ZIP
        # ----------------------------------------------------

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_file:

                if not zip_file.testzip() is None:
                    raise ValueError(
                        "The uploaded ZIP file is corrupted."
                    )

                _validate_zip_file(zip_file)

                # ------------------------------------------------
                # Create extraction directory
                # ------------------------------------------------

                os.makedirs(
                    extract_dir,
                    exist_ok=True,
                )

                # ------------------------------------------------
                # Safe extraction
                # ------------------------------------------------

                extraction_root = Path(
                    extract_dir
                ).resolve()

                for member in zip_file.infolist():

                    member_path = (
                        extraction_root
                        / member.filename
                    ).resolve()

                    # Make sure extracted path stays inside
                    # extraction directory.

                    try:
                        member_path.relative_to(
                            extraction_root
                        )
                    except ValueError:
                        raise ValueError(
                            f"Unsafe ZIP entry detected: "
                            f"{member.filename}"
                        )

                zip_file.extractall(extract_dir)

        except zipfile.BadZipFile:
            raise ValueError(
                "The uploaded file is not a valid ZIP archive."
            )

        return extract_dir

    except Exception:
        # If extraction fails, remove everything created for
        # this upload.

        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )

        raise

    finally:
        # Remove the original ZIP after extraction.

        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except OSError:
                pass


# ============================================================
# TEMPORARY FILE CLEANUP
# ============================================================

def cleanup_temp(path: str):
    """
    Remove the temporary directory created for a scan.
    """

    if not path:
        return

    target = Path(path)

    # The extracted directory's parent is the unique
    # temporary directory created for this scan.

    parent = target.parent

    if parent.exists():

        try:
            shutil.rmtree(
                parent,
                ignore_errors=True,
            )

        except OSError:
            pass