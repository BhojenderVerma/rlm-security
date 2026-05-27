"""
Crypto Misuse Detector.
Detects weak cryptographic algorithms, insecure modes, and poor key management.
"""

from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding


PATTERNS = [
    # ── Weak hash algorithms ──────────────────────────────────────────────
    {
        "regex": r'(hashlib\.md5|MD5\s*\(|new\s*MD5|MessageDigest\.getInstance\s*\(\s*["\']MD5)',
        "title": "Use of Weak Hash Algorithm: MD5",
        "description": "MD5 is cryptographically broken and should not be used for security purposes. "
                       "It is vulnerable to collision attacks.",
        "recommendation": "Replace MD5 with SHA-256 or SHA-3 for integrity checks. "
                          "For passwords, use bcrypt, argon2, or scrypt.",
        "cwe_id": "CWE-327",
        "confidence": "HIGH",
        "references": ["https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-131a.pdf"],
    },
    {
        "regex": r'(hashlib\.sha1|SHA1\s*\(|new\s*SHA1|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1)',
        "title": "Use of Weak Hash Algorithm: SHA-1",
        "description": "SHA-1 is deprecated for cryptographic use and has known collision vulnerabilities.",
        "recommendation": "Use SHA-256 or SHA-3 instead.",
        "cwe_id": "CWE-327",
        "confidence": "HIGH",
    },
    # ── Weak ciphers ─────────────────────────────────────────────────────
    {
        "regex": r'(DES\s*\.|Cipher\.getInstance\s*\(\s*["\']DES|new\s*DES)',
        "title": "Use of Weak Cipher: DES",
        "description": "DES has a 56-bit key length and is easily brute-forced.",
        "recommendation": "Use AES-256-GCM instead.",
        "cwe_id": "CWE-326",
        "confidence": "HIGH",
    },
    {
        "regex": r'(RC4|Cipher\.getInstance\s*\(\s*["\']RC4)',
        "title": "Use of Weak Cipher: RC4",
        "description": "RC4 is considered cryptographically broken.",
        "recommendation": "Replace with AES-256-GCM or ChaCha20-Poly1305.",
        "cwe_id": "CWE-327",
        "confidence": "HIGH",
    },
    # ── Insecure cipher modes ─────────────────────────────────────────────
    {
        "regex": r'(AES\.MODE_ECB|Cipher\.getInstance\s*\(\s*["\']AES/ECB|CryptoJS\.AES\.encrypt.*ECB)',
        "title": "AES in ECB Mode (Insecure)",
        "description": "AES-ECB does not use an IV and produces identical ciphertext for identical plaintext blocks, "
                       "leaking data patterns.",
        "recommendation": "Use AES-GCM (authenticated encryption) or AES-CBC with a random IV.",
        "cwe_id": "CWE-327",
        "confidence": "HIGH",
    },
    # ── Weak random number generation ────────────────────────────────────
    {
        "regex": r'(random\.random\s*\(\s*\)|Math\.random\s*\(\s*\)|new\s*Random\s*\(\s*\))',
        "title": "Weak Random Number Generator in Security Context",
        "description": "Non-cryptographic random generators are predictable and must not be used "
                       "for security-sensitive operations (tokens, keys, nonces).",
        "recommendation": "Use secrets.token_hex() (Python), crypto.randomBytes() (Node.js), "
                          "or SecureRandom (Java) for cryptographic randomness.",
        "cwe_id": "CWE-338",
        "confidence": "MEDIUM",
    },
    # ── Hardcoded IV / nonce ──────────────────────────────────────────────
    {
        "regex": r'(iv\s*=\s*b?["\'][0-9a-fA-F]{16,}["\']|nonce\s*=\s*b?["\'][0-9a-fA-F]{16,}["\'])',
        "title": "Hardcoded IV or Nonce",
        "description": "Using a static IV defeats the purpose of a cipher mode. "
                       "Two encryptions with the same key+IV may leak key-stream information.",
        "recommendation": "Generate a fresh random IV for every encryption operation.",
        "cwe_id": "CWE-329",
        "confidence": "HIGH",
    },
    # ── Insecure key sizes ────────────────────────────────────────────────
    {
        "regex": r'(RSA|genrsa|rsa\.generate_private_key).*\b(512|1024)\b',
        "title": "Weak RSA Key Size",
        "description": "RSA keys of 512 or 1024 bits are considered weak and can be factored.",
        "recommendation": "Use RSA keys of at least 2048 bits (3072 or 4096 preferred).",
        "cwe_id": "CWE-326",
        "confidence": "HIGH",
    },
]


class CryptoMisuseAnalyzer(BaseAnalyzer):
    name = "CryptoMisuseAnalyzer"
    category = "CRYPTO_MISUSE"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._scan_patterns(file_path, content, PATTERNS, severity="HIGH")
