"""
Debug & Information Exposure Detector.
Detects debug modes, verbose error handling, and sensitive data leakage.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'(?i)(DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug\s*:\s*true)',
        "title": "Debug Mode Enabled in Production Code",
        "description": "Debug mode is enabled. In production this exposes: stack traces, environment variables, source code, internal routes, and interactive debugger (Werkzeug PIN bypass = RCE).",
        "recommendation": "Set DEBUG=False in production. Load from environment: DEBUG = os.getenv('DEBUG', 'False') == 'True'.",
        "cwe_id": "CWE-489", "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_an_error_message"],
    },
    {
        "regex": r'(traceback\.print_exc|traceback\.format_exc)\s*\(',
        "title": "Stack Trace Exposed to User",
        "description": "Full stack trace may be returned to the user. Stack traces reveal internal paths, library versions, and logic — valuable intelligence for attackers.",
        "recommendation": "Log stack traces server-side only. Return generic error messages to clients.",
        "cwe_id": "CWE-209", "confidence": "MEDIUM",
    },
    {
        "regex": r'(print|console\.log|logger\.(debug|info))\s*\(.*\b(password|secret|token|key|credential|api_key)\b',
        "title": "Sensitive Data Logged/Printed",
        "description": "Sensitive values (password, secret, token) are being logged or printed. Logs may be stored insecurely or accessible to unauthorized parties.",
        "recommendation": "Never log sensitive values. Use masking: log the first 4 chars + '****'. Audit all logging statements.",
        "cwe_id": "CWE-532", "confidence": "HIGH",
    },
    {
        "regex": r'(app\.run|server\.listen)\s*\(.*debug\s*=\s*True',
        "title": "Server Started in Debug Mode",
        "description": "Web server started with debug=True. Werkzeug's interactive debugger provides a Python REPL with no authentication — instant RCE.",
        "recommendation": "Use debug=False. Set via environment: app.run(debug=os.getenv('FLASK_DEBUG', '0') == '1').",
        "cwe_id": "CWE-489", "confidence": "HIGH",
    },
    {
        "regex": r'(ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*["\']?\s*\]|CORS_ORIGIN_ALLOW_ALL\s*=\s*True)',
        "title": "Overly Permissive CORS/ALLOWED_HOSTS",
        "description": "All origins allowed via wildcard. This disables same-origin protection and can enable CSRF-like attacks from any website.",
        "recommendation": "Specify exact allowed origins. Never use '*' in production ALLOWED_HOSTS or CORS settings.",
        "cwe_id": "CWE-942", "confidence": "HIGH",
    },
    {
        "regex": r'(SHOW_ERRORS|display_errors|error_reporting)\s*[=:]\s*(True|On|E_ALL)',
        "title": "Error Display Enabled in Production",
        "description": "PHP/server error display is enabled. Detailed error messages reveal database structure, file paths, and stack traces.",
        "recommendation": "Disable error display in production: error_reporting(0); display_errors = Off;. Log errors to server-side files.",
        "cwe_id": "CWE-209", "confidence": "MEDIUM",
    },
    {
        "regex": r'(SECRET_KEY\s*=\s*["\']django-insecure-|SECRET_KEY\s*=\s*["\']changeme)',
        "title": "Default/Insecure Django SECRET_KEY",
        "description": "Django is using a default or obviously insecure SECRET_KEY. This key protects sessions, CSRF tokens, and signed data.",
        "recommendation": "Generate a strong key: python -c \"import secrets; print(secrets.token_hex(50))\" and store in environment variables.",
        "cwe_id": "CWE-798", "confidence": "HIGH",
    },
    {
        "regex": r'(response|res|resp)\.(send|json|write)\s*\(\s*(err|error|e|exception)',
        "title": "Raw Error Object Returned to Client",
        "description": "An error object is returned directly in the HTTP response. Error messages may contain stack traces, internal paths, or database details.",
        "recommendation": "Return generic error messages to clients. Log full errors server-side only.",
        "cwe_id": "CWE-209", "confidence": "MEDIUM",
    },
]

class DebugExposureAnalyzer(BaseAnalyzer):
    name = "DebugExposureAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="MEDIUM")
