"""
Open Redirect Detector.
Detects unvalidated redirect/forward vulnerabilities.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'(redirect|make_response.*Location)\s*\(\s*(.*request\.|.*req\.|.*params\.|.*input|.*url|.*next)',
        "title": "Open Redirect via Unvalidated URL Parameter",
        "description": "HTTP redirect to a URL derived from user input without validation. Attackers can redirect victims to phishing sites while using your trusted domain as a lure.",
        "recommendation": (
            "Validate redirect URLs:\n"
            "  1. Use an allowlist of permitted redirect destinations\n"
            "  2. Only allow relative paths (check not starting with //)\n"
            "  3. Use url_has_allowed_host_and_scheme() (Django) or equivalent"
        ),
        "cwe_id": "CWE-601", "confidence": "HIGH",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    },
    {
        "regex": r'(res\.redirect|response\.redirect|window\.location)\s*\(\s*(.*req\.|.*request\.|.*params\.|.*query\.url|.*query\.next)',
        "title": "Open Redirect in Node.js/Browser via User Parameter",
        "description": "Redirect target comes from user-controlled query parameter (url, next, redirect).",
        "recommendation": "Validate that redirect URLs are relative paths or from an allowlisted domain.",
        "cwe_id": "CWE-601", "confidence": "HIGH",
    },
    {
        "regex": r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$_(GET|POST|REQUEST)',
        "title": "Open Redirect via PHP header() with User Input",
        "description": "PHP Location header constructed from user GET/POST parameters.",
        "recommendation": "Validate redirect targets. Never use raw $_GET/$_POST in Location headers.",
        "cwe_id": "CWE-601", "confidence": "HIGH",
    },
    {
        "regex": r'(sendRedirect|setHeader\s*\(\s*["\']Location)',
        "title": "Open Redirect in Java Servlet",
        "description": "Java servlet redirect — ensure the target URL is validated and not user-controlled.",
        "recommendation": "Validate redirect URL against an allowlist. Reject URLs with different hosts.",
        "cwe_id": "CWE-601", "confidence": "LOW",
    },
]

class OpenRedirectAnalyzer(BaseAnalyzer):
    name = "OpenRedirectAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="MEDIUM")
