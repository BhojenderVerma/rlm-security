"""
Path Traversal Detector.
Detects file system operations with unvalidated user-controlled paths.
"""

from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding


PATTERNS = [
    {
        "regex": r'open\s*\(\s*(.*request\.|.*req\.|.*params\.|.*input|.*user)',
        "title": "Path Traversal via open() with User Input",
        "description": "File opened with a path derived from user input. "
                       "Attackers can use '../' sequences to access arbitrary files.",
        "recommendation": "Validate and sanitize file paths. Use os.path.realpath() and "
                          "verify the resulting path starts with the expected base directory.",
        "cwe_id": "CWE-22",
        "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    {
        "regex": r'os\.path\.join\s*\(.*\+\s*(request\.|req\.|params\.|input)',
        "title": "Path Traversal via os.path.join() with User Input",
        "description": "os.path.join() is used with user input. If input contains '../', "
                       "it can escape the intended directory.",
        "recommendation": "After joining, use os.path.realpath() and validate the path is within the allowed directory.",
        "cwe_id": "CWE-22",
        "confidence": "HIGH",
    },
    {
        "regex": r'send_file\s*\(\s*(.*request\.|.*req\.|.*params)',
        "title": "Path Traversal via send_file() (Flask)",
        "description": "Flask's send_file() called with user-controlled path.",
        "recommendation": "Use send_from_directory() instead, which validates paths automatically.",
        "cwe_id": "CWE-22",
        "confidence": "HIGH",
    },
    {
        "regex": r'\.\./',
        "title": "Hardcoded Directory Traversal Sequence",
        "description": "A '../' traversal sequence is present in the source. "
                       "If user-controlled, this can enable path traversal.",
        "recommendation": "Validate all file paths against an allowlist of safe directories.",
        "cwe_id": "CWE-22",
        "confidence": "LOW",
    },
    {
        "regex": r'(readFile|readFileSync|createReadStream)\s*\(\s*(.*req\.|.*request\.|.*params)',
        "title": "Path Traversal via fs.readFile (Node.js)",
        "description": "Node.js file read operation with user-controlled path.",
        "recommendation": "Validate paths using path.resolve() and confirm they are within the safe base directory.",
        "cwe_id": "CWE-22",
        "confidence": "HIGH",
    },
    {
        "regex": r'include\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        "title": "Remote/Local File Inclusion (PHP)",
        "description": "PHP include/require with user-controlled input can lead to file inclusion attacks.",
        "recommendation": "Use a whitelist of allowed file paths. Never include files based on user input directly.",
        "cwe_id": "CWE-22",
        "confidence": "HIGH",
    },
]


class PathTraversalAnalyzer(BaseAnalyzer):
    name = "PathTraversalAnalyzer"
    category = "PATH_TRAVERSAL"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="HIGH")
