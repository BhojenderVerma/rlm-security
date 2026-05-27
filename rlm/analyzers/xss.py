"""
XSS (Cross-Site Scripting) Detector.
Detects unescaped user input rendered in HTML contexts.
"""

from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding


PATTERNS = [
    {
        "regex": r'innerHTML\s*=\s*(.*\+|`.*\$\{|.*request\.|.*req\.|.*param)',
        "title": "XSS via innerHTML Assignment",
        "description": "Detected dynamic content assigned to innerHTML without sanitization. "
                       "This can allow attackers to inject malicious scripts.",
        "recommendation": "Use textContent instead of innerHTML, or sanitize HTML using DOMPurify before assignment.",
        "cwe_id": "CWE-79",
        "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/xss/"],
    },
    {
        "regex": r'dangerouslySetInnerHTML\s*=\s*\{\s*\{?\s*__html',
        "title": "XSS Risk: dangerouslySetInnerHTML (React)",
        "description": "dangerouslySetInnerHTML bypasses React's XSS protection. "
                       "Unescaped HTML can lead to script injection.",
        "recommendation": "Sanitize HTML content with DOMPurify before passing to dangerouslySetInnerHTML.",
        "cwe_id": "CWE-79",
        "confidence": "MEDIUM",
        "references": ["https://react.dev/reference/react-dom/components/common#dangerouslysetinnerhtml"],
    },
    {
        "regex": r'document\.write\s*\(',
        "title": "XSS via document.write()",
        "description": "document.write() with user-controlled data can lead to XSS.",
        "recommendation": "Avoid document.write(). Use safe DOM manipulation methods.",
        "cwe_id": "CWE-79",
        "confidence": "MEDIUM",
    },
    {
        "regex": r'outerHTML\s*=',
        "title": "XSS via outerHTML Assignment",
        "description": "Setting outerHTML from user input can inject malicious scripts.",
        "recommendation": "Sanitize all content before assigning to outerHTML.",
        "cwe_id": "CWE-79",
        "confidence": "HIGH",
    },
    {
        "regex": r'eval\s*\(\s*(.*request\.|.*req\.|.*params|.*input|.*user)',
        "title": "XSS / Code Injection via eval()",
        "description": "eval() with user-controlled input can lead to arbitrary code execution.",
        "recommendation": "Never use eval() with user input. Refactor to use safe alternatives.",
        "cwe_id": "CWE-79",
        "confidence": "HIGH",
    },
    {
        "regex": r'res\.send\s*\(.*\+\s*(req\.|request\.)',
        "title": "Reflected XSS in HTTP Response (Node.js)",
        "description": "User input from request is reflected directly into HTTP response without encoding.",
        "recommendation": "Escape or encode user input before including in HTML responses.",
        "cwe_id": "CWE-79",
        "confidence": "HIGH",
    },
]

PYTHON_PATTERNS = [
    {
        "regex": r'render\s*\(.*\|\s*safe',
        "title": "XSS via Jinja2 |safe Filter",
        "description": "Using |safe in Jinja2 templates bypasses auto-escaping. "
                       "User-controlled data marked as safe can lead to XSS.",
        "recommendation": "Avoid |safe on user-controlled data. Let Jinja2 auto-escape handle it.",
        "cwe_id": "CWE-79",
        "confidence": "HIGH",
    },
    {
        "regex": r'mark_safe\s*\(',
        "title": "XSS via Django mark_safe()",
        "description": "mark_safe() bypasses Django's auto-escaping. "
                       "If user-controlled data is passed, XSS is possible.",
        "recommendation": "Only use mark_safe() on trusted, server-generated content.",
        "cwe_id": "CWE-79",
        "confidence": "MEDIUM",
    },
]


class XSSAnalyzer(BaseAnalyzer):
    name = "XSSAnalyzer"
    category = "XSS"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        patterns = PATTERNS[:]
        if language == "python":
            patterns.extend(PYTHON_PATTERNS)

        return self._scan_patterns(file_path, content, patterns, severity="HIGH")
