"""
ZIP Archive Loader — extracts and loads source files from a ZIP archive.
"""

from __future__ import annotations
import io
import zipfile
from typing import List, Tuple
from ..core.sub_agent import SKIP_EXTENSIONS, EXTENSION_MAP

SUPPORTED_EXTENSIONS = set(EXTENSION_MAP.keys()) | {".txt", ".env", ".cfg", ".ini", ".conf", ".toml"}
MAX_FILE_SIZE = 1_000_000  # 1 MB


def load_zip(zip_path: str) -> List[Tuple[str, str]]:
    """
    Load all analyzable source files from a ZIP archive.

    Args:
        zip_path: Path to the .zip file.

    Returns:
        List of (relative_file_path, content) tuples.
    """
    files: List[Tuple[str, str]] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue

            name = info.filename
            _, ext = _splitext(name)

            if ext not in SUPPORTED_EXTENSIONS:
                continue
            if ext in SKIP_EXTENSIONS:
                continue
            if info.file_size > MAX_FILE_SIZE:
                continue
            if "__MACOSX" in name or name.startswith("."):
                continue

            try:
                raw = zf.read(name)
                content = raw.decode("utf-8", errors="replace")
                files.append((name, content))
            except Exception:
                continue

    return files


def _splitext(path: str) -> Tuple[str, str]:
    """Return (base, .ext) handling paths with multiple dots."""
    import os
    return os.path.splitext(path.lower())
