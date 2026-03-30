"""
intake/repo_cloner.py
Clones a GitHub repository locally with size enforcement.
"""

import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import CLONE_BASE_DIR, MAX_REPO_SIZE_MB


def _dir_size_mb(path: str) -> float:
    total = 0
    for dirpath, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total / (1024 * 1024)


def clone_repo(repo_url: str) -> str:
    """
    Clone repo_url into CLONE_BASE_DIR.
    Returns the local path on success.
    Raises RuntimeError on any failure.
    """
    # Basic validation
    if not repo_url or not str(repo_url).strip():
        raise RuntimeError("Empty repository URL provided to clone_repo.")

    if not (repo_url.startswith("http://") or repo_url.startswith("https://") or repo_url.startswith("git@")):
        raise RuntimeError("Invalid repository URL. Must start with http(s):// or git@")

    os.makedirs(CLONE_BASE_DIR, exist_ok=True)

    # Derive a clean folder name from the URL
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    local_path = os.path.join(CLONE_BASE_DIR, repo_name)

    # Remove any existing clone
    if os.path.exists(local_path):
        shutil.rmtree(local_path)

    print(f"[intake] Cloning: {repo_url}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, local_path],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        # Clean up possibly created folder
        if os.path.exists(local_path):
            try:
                shutil.rmtree(local_path)
            except Exception:
                pass
        raise RuntimeError(
            f"Git clone failed: {result.stderr.strip() or result.stdout.strip()}"
        )

    size_mb = _dir_size_mb(local_path)
    print(f"[intake] Cloned successfully. Size: {size_mb:.1f} MB")

    if size_mb > MAX_REPO_SIZE_MB:
        shutil.rmtree(local_path)
        raise RuntimeError(
            f"Repository is too large ({size_mb:.1f} MB). "
            f"Maximum allowed is {MAX_REPO_SIZE_MB} MB."
        )

    return local_path
