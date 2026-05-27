"""
GitHub Repository Loader — fetches source files from a public GitHub repo.
Supports both public repos (no token) and private repos (with GITHUB_TOKEN).
"""

from __future__ import annotations
import os
import re
import base64
import tempfile
import shutil
from typing import List, Tuple, Optional
import requests

from ..core.sub_agent import SKIP_EXTENSIONS, EXTENSION_MAP

SUPPORTED_EXTENSIONS = set(EXTENSION_MAP.keys()) | {".txt", ".env", ".cfg", ".ini", ".conf", ".toml"}
GITHUB_API = "https://api.github.com"
MAX_FILE_SIZE = 500_000  # 500 KB


def _parse_repo_url(url: str) -> Tuple[str, str, Optional[str]]:
    """
    Parse a GitHub URL into (owner, repo, branch).
    Supports:
      - https://github.com/owner/repo
      - https://github.com/owner/repo/tree/branch
    """
    # Strip trailing slash and .git
    url = url.rstrip("/").removesuffix(".git")
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)(?:/tree/([^/]+))?",
        url,
    )
    if not m:
        raise ValueError(f"Invalid GitHub URL: {url}")
    return m.group(1), m.group(2), m.group(3)


def load_github(
    url: str,
    token: Optional[str] = None,
    branch: Optional[str] = None,
) -> List[Tuple[str, str]]:
    """
    Fetch all source files from a GitHub repository via the GitHub API.

    Args:
        url: GitHub repository URL
        token: Optional GitHub personal access token
        branch: Branch to scan (defaults to repo default branch)

    Returns:
        List of (file_path, content) tuples
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    owner, repo, url_branch = _parse_repo_url(url)
    target_branch = branch or url_branch

    # Get default branch if not specified
    if not target_branch:
        resp = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers, timeout=15)
        resp.raise_for_status()
        target_branch = resp.json().get("default_branch", "main")

    # Get the full tree (recursive)
    tree_url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{target_branch}?recursive=1"
    resp = requests.get(tree_url, headers=headers, timeout=30)
    resp.raise_for_status()
    tree = resp.json()

    blobs = [
        item for item in tree.get("tree", [])
        if item["type"] == "blob" and _is_supported(item["path"])
        and item.get("size", 0) < MAX_FILE_SIZE
    ]

    files: List[Tuple[str, str]] = []

    for blob in blobs:
        try:
            content_url = (
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{blob['path']}"
                f"?ref={target_branch}"
            )
            resp = requests.get(content_url, headers=headers, timeout=15)
            if resp.status_code != 200:
                continue
            data = resp.json()
            encoded = data.get("content", "")
            raw = base64.b64decode(encoded.replace("\n", ""))
            text = raw.decode("utf-8", errors="replace")
            files.append((blob["path"], text))
        except Exception:
            continue

    return files


def _is_supported(path: str) -> bool:
    """Return True if the file extension is analyzable."""
    import os as _os
    _, ext = _os.path.splitext(path.lower())
    return ext in SUPPORTED_EXTENSIONS and ext not in SKIP_EXTENSIONS
