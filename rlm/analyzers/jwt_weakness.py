"""
JWT Weakness Detector.
Detects insecure JWT configurations and usage patterns.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'(jwt\.decode|jwt\.verify)\s*\([^)]*algorithms\s*=\s*\[\s*["\']none["\']',
        "title": "JWT Algorithm 'none' Accepted (Critical)",
        "description": "JWT decoded/verified with 'none' algorithm allowed. The 'none' algorithm disables signature verification — any attacker can forge tokens.",
        "recommendation": "Never allow 'none' in algorithms list. Always specify: algorithms=['HS256'] or ['RS256'].",
        "cwe_id": "CWE-347", "confidence": "HIGH",
        "references": ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
    },
    {
        "regex": r'jwt\.(encode|sign)\s*\(\s*.*secret\s*=\s*["\']["\']',
        "title": "JWT Signed with Empty Secret",
        "description": "JWT signed with an empty secret string. Any attacker knowing the algorithm can forge tokens.",
        "recommendation": "Use a cryptographically random secret of at least 256 bits. Load from environment variables.",
        "cwe_id": "CWE-321", "confidence": "HIGH",
    },
    {
        "regex": r'jwt\.(encode|sign)\s*\(\s*.*,\s*["\']secret["\']',
        "title": "JWT Signed with Weak/Default Secret",
        "description": "JWT signed with a literal 'secret' string — a commonly brute-forced value.",
        "recommendation": "Replace with a strong random secret: secrets.token_hex(32). Store in environment variables.",
        "cwe_id": "CWE-321", "confidence": "HIGH",
    },
    {
        "regex": r'jwt\.(decode|verify)\s*\([^)]*verify\s*=\s*False',
        "title": "JWT Signature Verification Disabled",
        "description": "JWT signature verification explicitly disabled (verify=False). Tokens are not validated — any token is accepted.",
        "recommendation": "Remove verify=False. JWT signatures must always be verified.",
        "cwe_id": "CWE-347", "confidence": "HIGH",
    },
    {
        "regex": r'jwt\.(encode|sign)\s*\([^)]*(?!exp)',
        "title": "JWT Possibly Missing Expiration Claim",
        "description": "JWT token created without an explicit 'exp' (expiration) claim. Non-expiring tokens can be reused indefinitely after compromise.",
        "recommendation": "Always include an 'exp' claim: {'exp': datetime.utcnow() + timedelta(hours=1)}.",
        "cwe_id": "CWE-613", "confidence": "LOW",
    },
    {
        "regex": r'(RS256|RS384|RS512)\s*.*\s*(HS256|HS384|HS512)',
        "title": "JWT Algorithm Confusion Risk (RS→HS)",
        "description": "Both RSA and HMAC algorithms listed. Attackers may exploit algorithm confusion: sign a token with the public key using HS256.",
        "recommendation": "Only list one algorithm family. Use RS256 for asymmetric or HS256 for symmetric — not both.",
        "cwe_id": "CWE-347", "confidence": "MEDIUM",
    },
]

class JWTWeaknessAnalyzer(BaseAnalyzer):
    name = "JWTWeaknessAnalyzer"
    category = "HARDCODED_SECRET"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="HIGH")
