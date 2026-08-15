import subprocess
import json
import shutil
import tempfile
import zipfile
import os
from pathlib import Path


def run_semgrep_scan(target_dir: str) -> list[dict]:
    """Run Semgrep against target_dir and return parsed findings."""
    result = subprocess.run(
        ["semgrep", "--config=auto", "--json", target_dir],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode not in (0, 1):  # 1 = findings found, still success
        raise RuntimeError(f"Semgrep failed: {result.stderr}")

    data = json.loads(result.stdout)
    return data.get("results", [])


def extract_zip_to_temp(zip_bytes: bytes) -> str:
    """Extract uploaded ZIP into a fresh temp directory. Returns the temp dir path."""
    temp_dir = tempfile.mkdtemp(prefix="sentinelforge_")
    zip_path = os.path.join(temp_dir, "upload.zip")

    with open(zip_path, "wb") as f:
        f.write(zip_bytes)

    extract_dir = os.path.join(temp_dir, "extracted")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)

    os.remove(zip_path)  # don't need the zip itself once extracted
    return extract_dir


def cleanup_temp(path: str):
    """Delete a temp directory and everything in it — zero retention."""
    parent = str(Path(path).parent)  # remove the whole sentinelforge_xxx dir, not just extracted/
    if os.path.exists(parent):
        shutil.rmtree(parent, ignore_errors=True)