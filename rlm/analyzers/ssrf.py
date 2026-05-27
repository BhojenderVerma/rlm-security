"""
SSRF (Server-Side Request Forgery) Detector.
Detects server-side HTTP requests made with user-controlled URLs.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'requests\.(get|post|put|delete|head|patch)\s*\(\s*(.*request\.|.*req\.|.*params\.|.*input|.*url|.*user)',
        "title": "SSRF via requests with User-Controlled URL",
        "description": "The requests library makes an HTTP call with a URL derived from user input. Attackers can redirect the server to internal services (169.254.x.x, 10.x.x.x, metadata endpoints).",
        "recommendation": (
            "Validate URLs strictly:\n"
            "  1. Parse with urllib.parse.urlparse()\n"
            "  2. Allowlist permitted hostnames/schemes\n"
            "  3. Block private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)\n"
            "  4. Use a dedicated SSRF-prevention library"
        ),
        "cwe_id": "CWE-918", "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    },
    {
        "regex": r'urllib\.(request\.urlopen|urlopen|urlretrieve)\s*\(\s*(.*request\.|.*req\.|.*input|.*url|.*user)',
        "title": "SSRF via urllib with User-Controlled URL",
        "description": "urllib.urlopen() called with user-supplied URL. Same SSRF risk as requests.",
        "recommendation": "Validate and allowlist URLs before fetching. Block requests to private/internal IP ranges.",
        "cwe_id": "CWE-918", "confidence": "HIGH",
    },
    {
        "regex": r'(axios|fetch|got|node-fetch|superagent)\s*\.\s*(get|post|put|delete)\s*\(\s*(.*req\.|.*request\.|.*params)',
        "title": "SSRF via HTTP Client with User Input (JS/Node)",
        "description": "JavaScript HTTP client called with user-controlled URL parameter.",
        "recommendation": "Validate URLs against an allowlist. Reject requests targeting private/loopback addresses.",
        "cwe_id": "CWE-918", "confidence": "HIGH",
    },
    {
        "regex": r'(file_get_contents|curl_setopt|curl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        "title": "SSRF via curl/file_get_contents with User Input (PHP)",
        "description": "PHP HTTP fetch function called with user-controlled URL. SSRF risk is critical in cloud environments.",
        "recommendation": "Never pass user input directly to curl or file_get_contents. Validate against strict allowlist.",
        "cwe_id": "CWE-918", "confidence": "HIGH",
    },
    {
        "regex": r'(HttpClient|OkHttpClient|CloseableHttpClient).*\.(get|post|execute)\s*\(.*\+',
        "title": "SSRF via Java HTTP Client with Concatenated URL",
        "description": "Java HTTP client executing a request with a dynamically built URL.",
        "recommendation": "Parse and validate URLs. Use a URL allowlist and block private IP ranges.",
        "cwe_id": "CWE-918", "confidence": "MEDIUM",
    },
]

class SSRFAnalyzer(BaseAnalyzer):
    name = "SSRFAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="HIGH")
