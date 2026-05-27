"""
Template Injection Detector.
Detects Server-Side Template Injection (SSTI) vulnerabilities.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'(Template|Environment)\s*\(.*\)\.from_string\s*\(\s*(.*request\.|.*req\.|.*input|.*user)',
        "title": "SSTI via Jinja2 Template.from_string() with User Input",
        "description": "Jinja2 Template.from_string() called with user-controlled template string allows Server-Side Template Injection. Attacker can execute: {{7*7}}, {{config}}, {{''.__class__.__mro__[1].__subclasses__()}}",
        "recommendation": "Never render user-supplied template strings. Use static templates with safe variable substitution only.",
        "cwe_id": "CWE-94", "confidence": "HIGH",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection"],
    },
    {
        "regex": r'render_template_string\s*\(\s*(.*request\.|.*req\.|.*input|.*user|.*\+|.*f")',
        "title": "SSTI via Flask render_template_string() with User Input",
        "description": "Flask's render_template_string() with user-controlled input is a critical SSTI vector.",
        "recommendation": "Use render_template() with static template files. Never pass user data as the template string.",
        "cwe_id": "CWE-94", "confidence": "HIGH",
    },
    {
        "regex": r'(\.render\s*\(\s*|\.renderString\s*\(\s*)(.*req\.|.*request\.|.*user|.*input)',
        "title": "Potential SSTI in Template Render Call",
        "description": "Template render called with user-controlled input as the template string.",
        "recommendation": "Separate template strings from user data. Use template variables, not dynamic template construction.",
        "cwe_id": "CWE-94", "confidence": "MEDIUM",
    },
    {
        "regex": r'(Mustache|Handlebars|nunjucks|pug|ejs)\.(render|compile)\s*\(\s*(.*req\.|.*request\.|.*user)',
        "title": "SSTI in JavaScript Template Engine",
        "description": "JavaScript template engine (Handlebars/Nunjucks/EJS/Pug) rendering user-controlled template string.",
        "recommendation": "Never compile or render user input as template code. Pass user data as template variables instead.",
        "cwe_id": "CWE-94", "confidence": "HIGH",
    },
    {
        "regex": r'(String\.format|MessageFormat\.format)\s*\(.*\+\s*(request\.|req\.|input)',
        "title": "Template/Format String Injection (Java)",
        "description": "Java format string built with user input. While less critical than SSTI, can cause information disclosure or crashes.",
        "recommendation": "Use parameterized format strings with fixed format patterns. Validate user input before use.",
        "cwe_id": "CWE-134", "confidence": "MEDIUM",
    },
]

class TemplateInjectionAnalyzer(BaseAnalyzer):
    name = "TemplateInjectionAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="HIGH")
