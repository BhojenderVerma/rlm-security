"""
Prototype Pollution & ReDoS Detector (JavaScript/TypeScript focused).
Also detects dangerous regex patterns that cause catastrophic backtracking.
"""
from __future__ import annotations
import re
from typing import List
from .base import BaseAnalyzer
from ..models import Finding, CodeLocation

PROTO_PATTERNS = [
    {
        "regex": r'__proto__\s*[:\[]',
        "title": "Prototype Pollution via __proto__",
        "description": "Direct assignment to __proto__ can pollute JavaScript's Object prototype, affecting all objects in the application. Can lead to privilege escalation or property injection.",
        "recommendation": "Use Object.create(null) for dictionaries. Validate and sanitize all keys from user input. Use JSON Schema validation.",
        "cwe_id": "CWE-1321", "confidence": "HIGH",
        "references": ["https://portswigger.net/web-security/prototype-pollution"],
    },
    {
        "regex": r'Object\.assign\s*\(\s*({}|Object\.create\(null\)|target)',
        "title": "Prototype Pollution Risk via Object.assign()",
        "description": "Object.assign() with user-controlled source objects can introduce __proto__ or constructor.prototype properties.",
        "recommendation": "Sanitize keys before merging: remove __proto__, constructor, prototype keys from user data.",
        "cwe_id": "CWE-1321", "confidence": "MEDIUM",
    },
    {
        "regex": r'(merge|deepMerge|extend|assign)\s*\(\s*\{?\s*\}?\s*,\s*(req\.|request\.|user|input)',
        "title": "Prototype Pollution via Unsafe Deep Merge",
        "description": "Deep merge/extend with user-controlled input object can pollute the prototype chain.",
        "recommendation": "Use safe merge libraries (lodash >= 4.17.21). Sanitize keys. Validate input with JSON Schema.",
        "cwe_id": "CWE-1321", "confidence": "MEDIUM",
    },
    {
        "regex": r'(constructor|prototype)\s*\[',
        "title": "Suspicious constructor/prototype Property Access",
        "description": "Dynamic access to constructor or prototype properties may indicate prototype pollution risk.",
        "recommendation": "Never allow user-controlled keys to access constructor or prototype. Use hasOwnProperty() checks.",
        "cwe_id": "CWE-1321", "confidence": "LOW",
    },
]

# Dangerous regex patterns that can cause ReDoS
REDOS_PATTERNS = [
    {
        "regex": r'new RegExp\s*\(\s*(.*req\.|.*request\.|.*input|.*user)',
        "title": "RegExp Injection / ReDoS via User-Controlled Regex",
        "description": "A regular expression is constructed from user input. Attackers can supply a catastrophically backtracking pattern causing 100% CPU usage (ReDoS).",
        "recommendation": "Never construct RegExp from user input. If needed, escape the input: input.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&').",
        "cwe_id": "CWE-400", "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/ReDoS"],
    },
    {
        "regex": r'\/\(\?:[^)]+\)\+\+|\/\(\?:[^)]+\)\{[0-9]+,\}/',
        "title": "Potentially Catastrophic Backtracking Regex Pattern",
        "description": "Regex with nested quantifiers (e.g., (a+)+ or (a{1,}) can cause catastrophic backtracking on malicious input.",
        "recommendation": "Simplify regex patterns. Use atomic groups or possessive quantifiers. Test with redos-checker tools.",
        "cwe_id": "CWE-1333", "confidence": "MEDIUM",
    },
]

class PrototypePollutionAnalyzer(BaseAnalyzer):
    name = "PrototypePollutionAnalyzer"
    category = "OTHER"

    SUPPORTED_LANGUAGES = {"javascript", "typescript"}

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        if language not in self.SUPPORTED_LANGUAGES:
            return []
        findings = self._scan_patterns(file_path, content, PROTO_PATTERNS, severity="HIGH")
        findings += self._scan_patterns(file_path, content, REDOS_PATTERNS, severity="MEDIUM")
        return findings
