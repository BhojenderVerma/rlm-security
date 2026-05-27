"""
Local Path Loader — walks a local directory and loads all source files.
"""

from __future__ import annotations
import os
from typing import List, Tuple, Set
from ..core.sub_agent import SKIP_EXTENSIONS, EXTENSION_MAP

# Directories to skip
SKIP_DIRS: Set[str] = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".pytest_cache",
    "venv", ".venv", "env", ".env",
    "dist", "build", ".next", ".nuxt",
    ".idea", ".vscode",
    "coverage", ".coverage",
    "vendor",
    "reports",   # generated scan reports contain code snippets → false positives
}

SUPPORTED_EXTENSIONS = set(EXTENSION_MAP.keys()) | {".txt", ".env", ".cfg", ".ini", ".conf", ".toml"}
MAX_FILE_SIZE = 1_000_000  # 1 MB


def load_local(path: str) -> List[Tuple[str, str]]:
    """
    Load all analyzable source files from a local path.

    Args:
        path: Absolute or relative path to a directory or single file.

    Returns:
        List of (relative_file_path, content) tuples.
    """
    path = os.path.abspath(path)

    if os.path.isfile(path):
        return _load_single_file(path, os.path.dirname(path))

    if not os.path.isdir(path):
        raise ValueError(f"Path not found: {path}")

    files: List[Tuple[str, str]] = []
    base = path

    for root, dirs, filenames in os.walk(path):
        # Prune skipped directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

        for filename in filenames:
            full_path = os.path.join(root, filename)
            _, ext = os.path.splitext(filename.lower())

            if ext not in SUPPORTED_EXTENSIONS:
                continue
            if ext in SKIP_EXTENSIONS:
                continue
            if os.path.getsize(full_path) > MAX_FILE_SIZE:
                continue

            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                rel_path = os.path.relpath(full_path, base)
                files.append((rel_path, content))
            except (PermissionError, OSError):
                continue

    return files


def _load_single_file(full_path: str, base: str) -> List[Tuple[str, str]]:
    """Load a single file."""
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        rel = os.path.relpath(full_path, base)
        return [(rel, content)]
    except Exception as exc:
        raise ValueError(f"Cannot read file {full_path}: {exc}")
