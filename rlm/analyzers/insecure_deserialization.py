"""
Insecure Deserialization Detector.
Detects unsafe deserialization of untrusted data — a critical RCE vector.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'pickle\.(loads|load|Unpickler)\s*\(',
        "title": "Insecure Deserialization via pickle",
        "description": "pickle.loads() deserializes Python objects from bytes. Deserializing untrusted data allows arbitrary code execution (__reduce__ magic method).",
        "recommendation": (
            "Never deserialize untrusted data with pickle.\n"
            "Use safe alternatives: json.loads(), msgpack, or protobuf.\n"
            "If pickle must be used, cryptographically sign the payload (HMAC) before serialization."
        ),
        "cwe_id": "CWE-502", "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
    },
    {
        "regex": r'yaml\.load\s*\(\s*(?!.*Loader\s*=\s*(yaml\.SafeLoader|SafeLoader))',
        "title": "Insecure Deserialization via yaml.load() without SafeLoader",
        "description": "yaml.load() without SafeLoader can execute arbitrary Python code via !!python/object tags in crafted YAML.",
        "recommendation": "Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        "cwe_id": "CWE-502", "confidence": "HIGH",
    },
    {
        "regex": r'marshal\.(loads|load)\s*\(',
        "title": "Insecure Deserialization via marshal",
        "description": "marshal.loads() on untrusted data can crash the interpreter or execute code.",
        "recommendation": "Use JSON or other safe serialization formats for untrusted data.",
        "cwe_id": "CWE-502", "confidence": "HIGH",
    },
    {
        "regex": r'ObjectInputStream\s*\(\s*(.*request\.|.*socket\.|.*stream)',
        "title": "Insecure Deserialization via Java ObjectInputStream",
        "description": "Java ObjectInputStream.readObject() on network data is a well-known RCE vector (Apache Commons Collections gadget chains).",
        "recommendation": (
            "Use a serialization filter (Java 9+ ObjectInputFilter) to whitelist allowed classes.\n"
            "Consider switching to JSON/Protobuf. Use libraries like Jackson with @JsonTypeInfo disabled."
        ),
        "cwe_id": "CWE-502", "confidence": "HIGH",
    },
    {
        "regex": r'(unserialize|deserialize)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
        "title": "Insecure Deserialization via PHP unserialize()",
        "description": "PHP unserialize() with user input can trigger __wakeup() / __destruct() gadget chains for RCE.",
        "recommendation": "Never call unserialize() on user input. Use json_decode() instead.",
        "cwe_id": "CWE-502", "confidence": "CRITICAL",
    },
    {
        "regex": r'(JSON\.parse|JSON\.stringify).*eval\s*\(',
        "title": "Unsafe JSON Parsing via eval()",
        "description": "Using eval() to parse JSON is a code injection risk. An attacker can break out of the JSON structure.",
        "recommendation": "Use JSON.parse() directly, never eval() on JSON strings.",
        "cwe_id": "CWE-502", "confidence": "HIGH",
    },
    {
        "regex": r'(shelve\.open|joblib\.load|torch\.load|numpy\.load)\s*\(',
        "title": "Potentially Unsafe Deserialization (ML/Data Libraries)",
        "description": "ML/data libraries (joblib, torch, numpy) use pickle internally for .load(). Loading untrusted model files can execute arbitrary code.",
        "recommendation": "Only load model files from trusted, verified sources. Use ONNX or SafeTensors format for model sharing.",
        "cwe_id": "CWE-502", "confidence": "MEDIUM",
    },
]

class InsecureDeserializationAnalyzer(BaseAnalyzer):
    name = "InsecureDeserializationAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="CRITICAL")
