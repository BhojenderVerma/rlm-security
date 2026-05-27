"""
SQL Injection Detector — detects unsanitized SQL query construction.
"""

from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding


PATTERNS = [
    {
        "regex": r'(execute|cursor\.execute|db\.execute|conn\.execute)\s*\(\s*["\'].*%[s|d]',
        "title": "SQL Injection via String Formatting",
        "description": "Detected SQL query built using Python string formatting (%s/%d). "
                       "User-controlled input passed this way can allow SQL injection attacks.",
        "recommendation": "Use parameterized queries or prepared statements. "
                          "Replace string interpolation with '?' or '%s' placeholders passed as a tuple.",
        "cwe_id": "CWE-89",
        "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    {
        "regex": r'(execute|cursor\.execute|db\.execute)\s*\(\s*f["\']',
        "title": "SQL Injection via f-string",
        "description": "Detected SQL query built using an f-string. "
                       "Embedding variables directly into SQL strings is vulnerable to injection.",
        "recommendation": "Use parameterized queries instead of f-strings for SQL construction.",
        "cwe_id": "CWE-89",
        "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    {
        "regex": r'(execute|cursor\.execute|db\.execute)\s*\(.*\+',
        "title": "SQL Injection via String Concatenation",
        "description": "Detected SQL query built by concatenating strings with '+'. "
                       "This pattern is a classic SQL injection vector.",
        "recommendation": "Never concatenate user input into SQL queries. Use ORM or parameterized queries.",
        "cwe_id": "CWE-89",
        "confidence": "MEDIUM",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    {
        "regex": r'SELECT\s+.+\s+FROM\s+.+\s+WHERE\s+.+\s*[+%]',
        "title": "Raw SQL with Dynamic WHERE Clause",
        "description": "Detected a raw SQL query with a dynamically built WHERE clause.",
        "recommendation": "Use an ORM (e.g., SQLAlchemy) or parameterized statements.",
        "cwe_id": "CWE-89",
        "confidence": "MEDIUM",
    },
    {
        "regex": r'query\s*=\s*["\'].*\+\s*(request\.|req\.|input|user_input|params)',
        "title": "SQL Query Built from Request Input",
        "description": "Detected a SQL query being constructed directly from HTTP request parameters.",
        "recommendation": "Sanitize and validate all inputs. Use parameterized queries.",
        "cwe_id": "CWE-89",
        "confidence": "HIGH",
    },
]

# JavaScript / Node.js patterns
JS_PATTERNS = [
    {
        "regex": r'(db|pool|connection|mysql|pg)\.query\s*\(\s*["`\'].*\$\{',
        "title": "SQL Injection via Template Literal (JS)",
        "description": "SQL query built using a JavaScript template literal with interpolated variables.",
        "recommendation": "Use parameterized queries. Pass values as an array to db.query().",
        "cwe_id": "CWE-89",
        "confidence": "HIGH",
    },
    {
        "regex": r'(db|pool|connection|mysql|pg)\.query\s*\(\s*["`\'].*\+\s*(req\.|request\.)',
        "title": "SQL Injection from Request Object (JS)",
        "description": "SQL query concatenated with request data in JavaScript.",
        "recommendation": "Use parameterized queries with placeholders.",
        "cwe_id": "CWE-89",
        "confidence": "HIGH",
    },
]


class SQLInjectionAnalyzer(BaseAnalyzer):
    name = "SQLInjectionAnalyzer"
    category = "SQL_INJECTION"

    SUPPORTED_LANGUAGES = {
        "python", "javascript", "typescript", "java", "php", "ruby", "go", "csharp",
    }

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        if language not in self.SUPPORTED_LANGUAGES:
            return []

        patterns = PATTERNS[:]
        if language in ("javascript", "typescript"):
            patterns.extend(JS_PATTERNS)

        return self._scan_patterns(file_path, content, patterns, severity="HIGH")
