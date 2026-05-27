"""
XXE (XML External Entity) Injection Detector.
Detects unsafe XML parsing configurations that allow external entity attacks.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'(etree\.parse|etree\.fromstring|ElementTree\.parse|minidom\.parse|SAXParser|xml\.sax\.parse)',
        "title": "Potentially Unsafe XML Parsing (XXE Risk)",
        "description": "XML parsed without disabling external entity resolution. If user-controlled XML is parsed, attackers can read local files or trigger SSRF via XXE.",
        "recommendation": (
            "Disable external entities:\n"
            "  parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
            "  or use defusedxml: import defusedxml.ElementTree as ET"
        ),
        "cwe_id": "CWE-611", "confidence": "MEDIUM",
        "references": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    },
    {
        "regex": r'xml\.dom\.minidom\.(parse|parseString)\s*\(',
        "title": "XXE Risk via minidom.parse()",
        "description": "minidom.parse() does not disable external entity resolution by default.",
        "recommendation": "Use defusedxml.minidom.parse() instead, which safely disables XXE.",
        "cwe_id": "CWE-611", "confidence": "MEDIUM",
    },
    {
        "regex": r'(DocumentBuilder|SAXParserFactory|XMLInputFactory).*\.(parse|newInstance)',
        "title": "XXE Risk in Java XML Parser",
        "description": "Java XML parser without explicit XXE protection. External entities may be resolved.",
        "recommendation": (
            "Disable external entities:\n"
            "  factory.setFeature('http://xml.org/sax/features/external-general-entities', false);\n"
            "  factory.setFeature('http://xml.org/sax/features/external-parameter-entities', false);"
        ),
        "cwe_id": "CWE-611", "confidence": "MEDIUM",
    },
    {
        "regex": r'libxml_disable_entity_loader\s*\(\s*false\s*\)',
        "title": "XXE Enabled in PHP (libxml_disable_entity_loader=false)",
        "description": "Entity loading is explicitly enabled in PHP XML parsing.",
        "recommendation": "Set libxml_disable_entity_loader(true) before parsing untrusted XML, or use PHP 8+ where this is deprecated.",
        "cwe_id": "CWE-611", "confidence": "HIGH",
    },
    {
        "regex": r'simplexml_load_(string|file)\s*\(',
        "title": "XXE Risk via simplexml_load_string/file (PHP)",
        "description": "PHP simplexml functions may process external entities if not configured safely.",
        "recommendation": "Pass LIBXML_NOENT | LIBXML_DTDLOAD flags carefully, or use libxml_disable_entity_loader(true) before calling.",
        "cwe_id": "CWE-611", "confidence": "LOW",
    },
]

class XXEAnalyzer(BaseAnalyzer):
    name = "XXEAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="HIGH")
