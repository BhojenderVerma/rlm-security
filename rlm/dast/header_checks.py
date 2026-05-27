"""
Security Header Checks — analyzes HTTP response headers for security misconfigurations.
"""
from __future__ import annotations
from typing import List, Dict


class HeaderFinding:
    def __init__(self, check: str, severity: str, title: str,
                 description: str, recommendation: str, actual: str = ""):
        self.check = check
        self.severity = severity
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.actual = actual  # what was actually found


def check_security_headers(url: str, headers: Dict[str, str]) -> List[HeaderFinding]:
    """Run all security header checks against a response's headers."""
    findings: List[HeaderFinding] = []
    h = {k.lower(): v for k, v in headers.items()}

    # ── Content-Security-Policy ─────────────────────────────────────────────
    csp = h.get("content-security-policy", "")
    if not csp:
        findings.append(HeaderFinding(
            check="CSP_MISSING", severity="HIGH",
            title="Missing Content-Security-Policy Header",
            description="No CSP header found. CSP prevents XSS by restricting which scripts, styles, and resources can execute on the page.",
            recommendation="Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
            actual="(not set)",
        ))
    elif "unsafe-inline" in csp and "script-src" in csp:
        findings.append(HeaderFinding(
            check="CSP_UNSAFE_INLINE", severity="MEDIUM",
            title="Content-Security-Policy Allows 'unsafe-inline'",
            description="'unsafe-inline' in script-src defeats XSS protection. Inline scripts are allowed, undermining CSP.",
            recommendation="Remove 'unsafe-inline'. Use nonces or hashes for legitimate inline scripts.",
            actual=csp[:120],
        ))
    if csp and "unsafe-eval" in csp:
        findings.append(HeaderFinding(
            check="CSP_UNSAFE_EVAL", severity="MEDIUM",
            title="Content-Security-Policy Allows 'unsafe-eval'",
            description="'unsafe-eval' allows eval(), setTimeout(string), and new Function() — dangerous XSS vectors.",
            recommendation="Remove 'unsafe-eval'. Refactor code to avoid dynamic code evaluation.",
            actual=csp[:120],
        ))

    # ── HSTS ────────────────────────────────────────────────────────────────
    hsts = h.get("strict-transport-security", "")
    if not hsts:
        findings.append(HeaderFinding(
            check="HSTS_MISSING", severity="HIGH",
            title="Missing Strict-Transport-Security (HSTS) Header",
            description="No HSTS header. Browsers may connect over HTTP first, enabling MITM attacks and SSL stripping.",
            recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            actual="(not set)",
        ))
    elif "max-age=0" in hsts:
        findings.append(HeaderFinding(
            check="HSTS_ZERO_MAXAGE", severity="HIGH",
            title="HSTS max-age=0 (HSTS Disabled)",
            description="HSTS is set with max-age=0, which revokes the HSTS policy. Connections can be downgraded to HTTP.",
            recommendation="Set max-age to at least 31536000 (1 year).",
            actual=hsts,
        ))
    elif "max-age=" in hsts:
        try:
            ma = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
            if ma < 86400:
                findings.append(HeaderFinding(
                    check="HSTS_SHORT_MAXAGE", severity="MEDIUM",
                    title="HSTS max-age Too Short",
                    description=f"HSTS max-age is only {ma} seconds. Recommended minimum is 31536000 (1 year).",
                    recommendation="Increase max-age: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    actual=hsts,
                ))
        except (ValueError, IndexError):
            pass

    # ── X-Frame-Options ─────────────────────────────────────────────────────
    xfo = h.get("x-frame-options", "")
    csp_frame = "frame-ancestors" in csp if csp else False
    if not xfo and not csp_frame:
        findings.append(HeaderFinding(
            check="XFO_MISSING", severity="MEDIUM",
            title="Missing X-Frame-Options (Clickjacking Risk)",
            description="Page can be embedded in an <iframe> on any domain. Attackers can overlay invisible frames to hijack clicks.",
            recommendation="Add: X-Frame-Options: DENY  or use CSP: frame-ancestors 'none'",
            actual="(not set)",
        ))
    elif xfo.upper() == "ALLOWALL":
        findings.append(HeaderFinding(
            check="XFO_ALLOWALL", severity="HIGH",
            title="X-Frame-Options: ALLOWALL (Clickjacking Enabled)",
            description="X-Frame-Options is set to ALLOWALL, explicitly allowing framing from any origin.",
            recommendation="Change to: X-Frame-Options: DENY or SAMEORIGIN",
            actual=xfo,
        ))

    # ── X-Content-Type-Options ──────────────────────────────────────────────
    xcto = h.get("x-content-type-options", "")
    if not xcto:
        findings.append(HeaderFinding(
            check="XCTO_MISSING", severity="LOW",
            title="Missing X-Content-Type-Options Header",
            description="Without 'nosniff', browsers may MIME-sniff responses and execute non-script files as scripts.",
            recommendation="Add: X-Content-Type-Options: nosniff",
            actual="(not set)",
        ))

    # ── Referrer-Policy ─────────────────────────────────────────────────────
    rp = h.get("referrer-policy", "")
    if not rp:
        findings.append(HeaderFinding(
            check="RP_MISSING", severity="LOW",
            title="Missing Referrer-Policy Header",
            description="Without a Referrer-Policy, the full URL (including query params with tokens) may be sent as the Referer header to third parties.",
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            actual="(not set)",
        ))
    elif rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append(HeaderFinding(
            check="RP_UNSAFE", severity="MEDIUM",
            title="Weak Referrer-Policy (Leaks Full URL)",
            description=f"Referrer-Policy '{rp}' may leak sensitive URL parameters to third-party sites.",
            recommendation="Use: Referrer-Policy: strict-origin-when-cross-origin",
            actual=rp,
        ))

    # ── Permissions-Policy ──────────────────────────────────────────────────
    pp = h.get("permissions-policy", "") or h.get("feature-policy", "")
    if not pp:
        findings.append(HeaderFinding(
            check="PP_MISSING", severity="INFO",
            title="Missing Permissions-Policy Header",
            description="No Permissions-Policy set. Browser features (camera, microphone, geolocation) may be accessible to embedded content.",
            recommendation="Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            actual="(not set)",
        ))

    # ── Server Information Disclosure ────────────────────────────────────────
    server = h.get("server", "")
    if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "php/", "express/"]):
        findings.append(HeaderFinding(
            check="SERVER_DISCLOSURE", severity="LOW",
            title="Server Version Disclosed in Header",
            description=f"Server header reveals software version: '{server}'. Attackers can target known vulnerabilities for this specific version.",
            recommendation="Remove or obscure the Server header. Configure server to suppress version information.",
            actual=server,
        ))

    x_powered = h.get("x-powered-by", "")
    if x_powered:
        findings.append(HeaderFinding(
            check="XPOWERED_DISCLOSURE", severity="LOW",
            title="Technology Disclosed via X-Powered-By Header",
            description=f"X-Powered-By reveals: '{x_powered}'. Exposes backend technology stack.",
            recommendation="Remove X-Powered-By header. In Express.js: app.disable('x-powered-by')",
            actual=x_powered,
        ))

    # ── CORS ─────────────────────────────────────────────────────────────────
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(HeaderFinding(
            check="CORS_WILDCARD_CREDENTIALS", severity="HIGH",
            title="CORS: Wildcard Origin with Credentials=true",
            description="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true allows any site to make credentialed cross-origin requests. This is a CORS misconfiguration browsers actually block, but indicates dangerous intent.",
            recommendation="Specify exact allowed origins: Access-Control-Allow-Origin: https://yourdomain.com",
            actual=f"ACAO={acao}, ACAC={acac}",
        ))
    elif acao == "*":
        findings.append(HeaderFinding(
            check="CORS_WILDCARD", severity="MEDIUM",
            title="CORS: Wildcard Origin Allowed",
            description="Any origin can read responses from this endpoint. For public APIs this may be intentional, but for authenticated APIs it's dangerous.",
            recommendation="Replace wildcard with specific allowed origins unless this is a fully public API.",
            actual=acao,
        ))

    return findings
