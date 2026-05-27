"""
NoSQL Injection Detector.
Detects MongoDB, Redis, and other NoSQL query injection vulnerabilities.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'(find|find_one|find_many|update|delete_one|delete_many|aggregate)\s*\(\s*\{[^}]*(request\.|req\.|input|user|params)',
        "title": "NoSQL Injection via MongoDB Query with User Input",
        "description": "MongoDB query built directly from user input. Attackers can inject operators like {$gt: ''} or {$where: 'this.password...'} to bypass authentication or dump all data.",
        "recommendation": (
            "Sanitize all MongoDB query parameters:\n"
            "  1. Cast to expected types (int, str) before querying\n"
            "  2. Use libraries like mongo-sanitize (Node) or bleach (Python)\n"
            "  3. Reject or strip keys starting with '$'"
        ),
        "cwe_id": "CWE-943", "confidence": "HIGH",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
    },
    {
        "regex": r'\$where\s*:\s*["\']',
        "title": "MongoDB $where Operator (Code Injection Risk)",
        "description": "$where executes JavaScript on the MongoDB server. If any part is user-controlled, it's a code injection.",
        "recommendation": "Avoid $where entirely. Use standard MongoDB query operators instead.",
        "cwe_id": "CWE-943", "confidence": "HIGH",
    },
    {
        "regex": r'(collection\.find|db\.collection)\s*\(\s*\{.*\$',
        "title": "MongoDB Query with Operator — Review for Injection",
        "description": "MongoDB query using operators may be vulnerable if any value comes from user input.",
        "recommendation": "Ensure all query values are validated and typed. Never allow users to control operator names.",
        "cwe_id": "CWE-943", "confidence": "LOW",
    },
    {
        "regex": r'r\.table\s*\([^)]+\)\s*\.(filter|get)\s*\(\s*(.*request\.|.*req\.|.*input)',
        "title": "NoSQL Injection via RethinkDB Query with User Input",
        "description": "RethinkDB query with user-supplied filter values without sanitization.",
        "recommendation": "Validate all input types before using in RethinkDB queries.",
        "cwe_id": "CWE-943", "confidence": "HIGH",
    },
    {
        "regex": r'redis\.(get|set|hget|hset|lpush|rpush|zadd|eval)\s*\(\s*(.*request\.|.*req\.|.*input)',
        "title": "Redis Command Injection via User Input",
        "description": "Redis command executed with user-controlled key/value. In EVAL commands, this can lead to Lua code injection.",
        "recommendation": "Validate Redis key names. Never use user input in EVAL scripts. Use parameterized Redis commands.",
        "cwe_id": "CWE-943", "confidence": "MEDIUM",
    },
]

class NoSQLInjectionAnalyzer(BaseAnalyzer):
    name = "NoSQLInjectionAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="HIGH")
