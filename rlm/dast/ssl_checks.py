"""
SSL/TLS Checker — verifies certificate validity and TLS configuration.
"""
from __future__ import annotations
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class SSLFinding:
    check: str
    severity: str
    title: str
    description: str
    recommendation: str
    evidence: str = ""


def check_ssl(hostname: str, port: int = 443) -> List[SSLFinding]:
    """Check SSL/TLS configuration for a host."""
    findings: List[SSLFinding] = []

    # ── Fetch certificate info ───────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, port))
            cert = s.getpeercert()
            protocol = s.version()
            cipher = s.cipher()  # (name, version, bits)
    except ssl.SSLCertVerificationError as e:
        findings.append(SSLFinding(
            check="SSL_CERT_INVALID",
            severity="CRITICAL",
            title="SSL Certificate Validation Failed",
            description=f"The SSL certificate is invalid or untrusted: {e}",
            recommendation="Obtain a valid certificate from a trusted CA (Let's Encrypt is free). Ensure the certificate matches the hostname.",
            evidence=str(e),
        ))
        return findings
    except ssl.SSLError as e:
        findings.append(SSLFinding(
            check="SSL_ERROR",
            severity="HIGH",
            title="SSL/TLS Connection Error",
            description=f"SSL handshake failed: {e}",
            recommendation="Ensure the server supports TLS 1.2 or higher and has a valid certificate.",
            evidence=str(e),
        ))
        return findings
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Not an HTTPS host or unreachable — skip SSL checks
        return []

    # ── Certificate expiry ───────────────────────────────────────────────────
    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days

            if days_left < 0:
                findings.append(SSLFinding(
                    check="SSL_CERT_EXPIRED",
                    severity="CRITICAL",
                    title="SSL Certificate Has Expired",
                    description=f"The certificate expired {abs(days_left)} days ago.",
                    recommendation="Renew the certificate immediately. Consider automating renewal with Let's Encrypt + certbot.",
                    evidence=f"Expired: {not_after}",
                ))
            elif days_left < 14:
                findings.append(SSLFinding(
                    check="SSL_CERT_EXPIRING_SOON",
                    severity="HIGH",
                    title=f"SSL Certificate Expires in {days_left} Days",
                    description="Certificate is about to expire. Browsers will show security warnings.",
                    recommendation="Renew the certificate now. Automate renewal to prevent future expiry.",
                    evidence=f"Expires: {not_after}",
                ))
            elif days_left < 30:
                findings.append(SSLFinding(
                    check="SSL_CERT_EXPIRING_SOON",
                    severity="MEDIUM",
                    title=f"SSL Certificate Expires in {days_left} Days",
                    description="Certificate expires within 30 days.",
                    recommendation="Schedule certificate renewal soon.",
                    evidence=f"Expires: {not_after}",
                ))
        except (ValueError, TypeError):
            pass

    # ── Protocol version ─────────────────────────────────────────────────────
    if protocol:
        if protocol in ("TLSv1", "SSLv3", "SSLv2"):
            findings.append(SSLFinding(
                check="WEAK_TLS_PROTOCOL",
                severity="HIGH",
                title=f"Weak TLS Protocol in Use: {protocol}",
                description=f"The server negotiated {protocol} which is deprecated and known to be insecure (POODLE, BEAST attacks).",
                recommendation="Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3.",
                evidence=f"Negotiated protocol: {protocol}",
            ))
        elif protocol == "TLSv1.1":
            findings.append(SSLFinding(
                check="DEPRECATED_TLS_PROTOCOL",
                severity="MEDIUM",
                title="Deprecated TLS 1.1 in Use",
                description="TLS 1.1 is deprecated. Most major browsers have removed support.",
                recommendation="Configure server to use TLS 1.2 minimum. Enable TLS 1.3.",
                evidence=f"Negotiated protocol: {protocol}",
            ))

    # ── Cipher strength ──────────────────────────────────────────────────────
    if cipher:
        cipher_name, _, bits = cipher
        if bits and bits < 128:
            findings.append(SSLFinding(
                check="WEAK_CIPHER",
                severity="HIGH",
                title=f"Weak Cipher Suite: {cipher_name} ({bits} bits)",
                description=f"Cipher with only {bits}-bit key is considered weak and may be brute-forceable.",
                recommendation="Configure server to use strong ciphers: ECDHE+AES256+GCM. Disable RC4, DES, 3DES, export ciphers.",
                evidence=f"Cipher: {cipher_name}, {bits} bits",
            ))
        if any(w in (cipher_name or "").upper() for w in ["RC4", "DES", "EXPORT", "NULL", "ANON"]):
            findings.append(SSLFinding(
                check="WEAK_CIPHER_NAME",
                severity="HIGH",
                title=f"Insecure Cipher Suite: {cipher_name}",
                description=f"The cipher '{cipher_name}' is known to be insecure.",
                recommendation="Disable weak cipher suites. Use only AES-GCM or ChaCha20-Poly1305.",
                evidence=f"Negotiated cipher: {cipher_name}",
            ))

    # ── Self-signed cert ─────────────────────────────────────────────────────
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    if issuer == subject:
        findings.append(SSLFinding(
            check="SELF_SIGNED_CERT",
            severity="HIGH",
            title="Self-Signed SSL Certificate",
            description="The certificate is self-signed and not trusted by browsers. Users will see security warnings.",
            recommendation="Replace with a certificate from a trusted CA (Let's Encrypt is free).",
            evidence=f"Issuer == Subject: {issuer.get('commonName', '')}",
        ))

    return findings
