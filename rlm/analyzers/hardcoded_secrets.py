"""
Hardcoded Secrets Detector.
Detects API keys, passwords, tokens, and other credentials embedded in source code.
Uses regex pattern matching + Shannon entropy analysis to reduce false positives.
"""

from __future__ import annotations
import re
import math
from typing import List
from .base import BaseAnalyzer
from ..models import Finding, CodeLocation


# ── Entropy helpers ─────────────────────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


HIGH_ENTROPY_THRESHOLD = 3.5  # bits per character

# ── Patterns ────────────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    {
        "regex": r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
        "title": "Hardcoded Password",
        "description": "A plaintext password is hardcoded in source code.",
        "recommendation": "Move credentials to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
        "cwe_id": "CWE-798",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{10,}["\']',
        "title": "Hardcoded API Key",
        "description": "An API key is hardcoded in source code. This exposes the key if the code is shared.",
        "recommendation": "Store API keys in environment variables and load them at runtime.",
        "cwe_id": "CWE-798",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)(secret|secret_key|app_secret)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{10,}["\']',
        "title": "Hardcoded Secret Key",
        "description": "A secret key is embedded in source code.",
        "recommendation": "Use environment variables. Never commit secrets to version control.",
        "cwe_id": "CWE-798",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)(access_token|auth_token|bearer)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-\.]{10,}["\']',
        "title": "Hardcoded Access Token",
        "description": "An access/bearer token is hardcoded.",
        "recommendation": "Retrieve tokens dynamically via OAuth flows or secret managers.",
        "cwe_id": "CWE-798",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)private[_-]?key\s*[=:]\s*["\'][\-A-Za-z0-9+/=\s]{20,}["\']',
        "title": "Hardcoded Private Key",
        "description": "A private key material is embedded in source code.",
        "recommendation": "Store private keys in secure key stores, not source code.",
        "cwe_id": "CWE-321",
        "confidence": "HIGH",
    },
    {
        "regex": r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
        "title": "Embedded PEM Private Key",
        "description": "A PEM-formatted private key is present in source code.",
        "recommendation": "Remove the key immediately and rotate it. Store keys outside the codebase.",
        "cwe_id": "CWE-321",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\'][A-Z0-9/+]{16,}["\']',
        "title": "Hardcoded AWS Credential",
        "description": "AWS credentials are hardcoded in source code.",
        "recommendation": "Use IAM roles, instance profiles, or AWS Secrets Manager.",
        "cwe_id": "CWE-798",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)(database_url|db_url|connection_string)\s*[=:]\s*["\'][a-z]+://[^"\']{5,}["\']',
        "title": "Hardcoded Database Connection String",
        "description": "A database connection string with embedded credentials is hardcoded.",
        "recommendation": "Use environment variables for database connection strings.",
        "cwe_id": "CWE-798",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)(github_token|gh_token|gitlab_token)\s*[=:]\s*["\'][A-Za-z0-9_\-]{10,}["\']',
        "title": "Hardcoded Git Token",
        "description": "A GitHub/GitLab personal access token is hardcoded.",
        "recommendation": "Store tokens as environment variables and use CI/CD secret management.",
        "cwe_id": "CWE-798",
        "confidence": "HIGH",
    },
    {
        "regex": r'(?i)(slack_token|slack_webhook)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{10,}["\']',
        "title": "Hardcoded Slack Token/Webhook",
        "description": "A Slack token or webhook URL is hardcoded in source.",
        "recommendation": "Store Slack credentials as environment variables.",
        "cwe_id": "CWE-798",
        "confidence": "MEDIUM",
    },
]

# Patterns to skip (common false positives)
IGNORE_PATTERNS = [
    r'(?i)(password|secret)\s*=\s*["\'](\s*|your[_-]?password|<password>|\*+|example|test|placeholder|changeme|todo|xxx)["\']',
    r'(?i)#.*password',  # commented-out lines
]


class HardcodedSecretsAnalyzer(BaseAnalyzer):
    name = "HardcodedSecretsAnalyzer"
    category = "HARDCODED_SECRET"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Skip binary-looking files
        if "\x00" in content:
            return []

        for pat in SECRET_PATTERNS:
            regex = re.compile(pat["regex"])
            ignore_compiled = [re.compile(ig) for ig in IGNORE_PATTERNS]

            for i, line in enumerate(lines):
                # Skip comment-only lines
                stripped = line.strip()
                if stripped.startswith(("#", "//", "--", "*")):
                    continue

                if regex.search(line):
                    # Check ignore patterns
                    if any(ig.search(line) for ig in ignore_compiled):
                        continue

                    # Entropy check on the matched value
                    val_match = re.search(r'["\']([A-Za-z0-9+/=_\-\.]{8,})["\']', line)
                    if val_match:
                        val = val_match.group(1)
                        if _shannon_entropy(val) < 2.5:  # likely a placeholder
                            continue

                    findings.append(
                        Finding(
                            location=CodeLocation(
                                file=file_path,
                                line_start=i + 1,
                                line_end=i + 1,
                            ),
                            severity="CRITICAL",
                            category=self.category,
                            title=pat["title"],
                            description=pat["description"],
                            code_snippet=self._get_snippet(lines, i),
                            recommendation=pat["recommendation"],
                            cwe_id=pat.get("cwe_id"),
                            confidence=pat.get("confidence", "MEDIUM"),
                        )
                    )

        return findings
