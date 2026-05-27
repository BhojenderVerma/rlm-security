"""
Sub-LLM Agent — responsible for scanning a single file.
Runs all security analyzers and optionally uses LLM for deeper analysis.
"""

from __future__ import annotations
import time
import os
from typing import List, Optional
from ..models import Finding, FileScanResult
from ..analyzers import ALL_ANALYZERS

# ── Language detection ───────────────────────────────────────────────────────

EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".env": "env",
    ".txt": "text",
    ".toml": "toml",
    ".cfg": "config",
    ".ini": "config",
    ".conf": "config",
}

# Files we skip (binary/generated/non-source)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".exe", ".dll", ".so", ".dylib",
    ".lock", ".min.js", ".min.css",
    ".map",
}

MAX_FILE_SIZE_BYTES = 500_000  # 500 KB

# ── False-positive suppression ───────────────────────────────────────────────
# Files that define detection patterns for the analyzers will naturally contain
# the very strings they detect. We skip deep analysis on these files and only
# run the InsecureDeps analyzer (which is manifest-file based and safe).
SELF_SCAN_SKIP_PATHS = {
    # Our own analyzer source files — contain regex patterns as string literals
    "rlm/analyzers/sql_injection.py",
    "rlm/analyzers/xss.py",
    "rlm/analyzers/hardcoded_secrets.py",
    "rlm/analyzers/path_traversal.py",
    "rlm/analyzers/crypto_misuse.py",
    "rlm/analyzers/insecure_deps.py",
    "rlm/analyzers/base.py",
    # New analyzers
    "rlm/analyzers/command_injection.py",
    "rlm/analyzers/xxe.py",
    "rlm/analyzers/ssrf.py",
    "rlm/analyzers/insecure_deserialization.py",
    "rlm/analyzers/template_injection.py",
    "rlm/analyzers/nosql_injection.py",
    "rlm/analyzers/jwt_weakness.py",
    "rlm/analyzers/debug_exposure.py",
    "rlm/analyzers/open_redirect.py",
    "rlm/analyzers/prototype_pollution.py",
    # Web dashboard demo data — intentionally contains vulnerable code examples
    "web/app.js",
    "rlm/output/pdf_report.py",  # contains fix code examples as strings
}


def _is_self_scan_file(file_path: str) -> bool:
    """Return True if this file should skip pattern-based analyzers (false-positive prevention)."""
    # Normalise path separators
    normalized = file_path.replace("\\", "/")
    return any(normalized.endswith(skip) or skip in normalized for skip in SELF_SCAN_SKIP_PATHS)


def detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    _, ext = os.path.splitext(file_path.lower())
    return EXTENSION_MAP.get(ext, "unknown")


def should_skip(file_path: str) -> bool:
    """Return True for binary / generated files that should not be analyzed."""
    _, ext = os.path.splitext(file_path.lower())
    if ext in SKIP_EXTENSIONS:
        return True
    # Skip minified files by name convention
    base = os.path.basename(file_path).lower()
    if ".min." in base or "bundle." in base:
        return True
    return False


class SubAgent:
    """
    Per-file analysis agent.
    Instantiated by RootAgent for each file and runs all analyzers.
    """

    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        # Instantiate all analyzers once per sub-agent
        self.analyzers = [cls(llm_client=llm_client) for cls in ALL_ANALYZERS]

    def scan_file(self, file_path: str, content: str) -> FileScanResult:
        """
        Scan a single file and return its results.
        Args:
            file_path: Relative path (used in reports)
            content: Full text content of the file
        Returns:
            FileScanResult with all findings
        """
        start = time.time()

        # Skip non-analyzable files
        if should_skip(file_path) or not content.strip():
            return FileScanResult(
                file_path=file_path,
                language="unknown",
                lines_analyzed=0,
                findings=[],
                scan_duration_ms=0,
            )

        # Truncate extremely large files
        if len(content.encode("utf-8", errors="replace")) > MAX_FILE_SIZE_BYTES:
            content = content[:MAX_FILE_SIZE_BYTES]

        language = detect_language(file_path)
        lines = content.splitlines()

        # Determine which analyzers to run
        # Self-scan files (analyzer source, demo data) skip pattern analyzers
        # to prevent false positives from their own detection regex strings.
        is_self = _is_self_scan_file(file_path)
        from ..analyzers import InsecureDepsAnalyzer
        active_analyzers = (
            [a for a in self.analyzers if isinstance(a, InsecureDepsAnalyzer)]
            if is_self
            else self.analyzers
        )

        all_findings: List[Finding] = []
        for analyzer in active_analyzers:
            try:
                findings = analyzer.analyze(file_path, content, language)
                all_findings.extend(findings)
            except Exception:
                # Individual analyzer failures must not crash the scan
                pass

        elapsed_ms = (time.time() - start) * 1000

        return FileScanResult(
            file_path=file_path,
            language=language,
            lines_analyzed=len(lines),
            findings=all_findings,
            scan_duration_ms=round(elapsed_ms, 2),
        )
