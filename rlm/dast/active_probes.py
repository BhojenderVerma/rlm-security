"""
Active Probes — tests specific endpoints for XSS, SQLi, SSRF, Open Redirect.
Uses safe, non-destructive payloads. Only tests what is found by the crawler.
"""
from __future__ import annotations
import re
import time
from typing import List, Optional, Dict
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote

from .crawler import CrawlResult


class ProbeFinding:
    def __init__(self, check: str, severity: str, title: str,
                 url: str, param: str, payload: str,
                 description: str, recommendation: str, evidence: str = ""):
        self.check = check
        self.severity = severity
        self.title = title
        self.url = url
        self.param = param
        self.payload = payload
        self.description = description
        self.recommendation = recommendation
        self.evidence = evidence


# ── XSS Payloads ─────────────────────────────────────────────────────────────
# Reflection-detection payloads — look for literal reflection in response body
XSS_PROBES = [
    ('<script>alert("rlm-xss")</script>', r'<script>alert\("rlm-xss"\)</script>'),
    ('"onmouseover="alert(1)', r'"onmouseover="alert'),
    ("'><svg/onload=alert(1)>", r"svg/onload=alert"),
    ("<img src=x onerror=alert(1)>", r"<img src=x onerror=alert"),
]

# ── SQLi Error Signatures ────────────────────────────────────────────────────
SQLI_PROBES = ["'", "''", "`", "1' OR '1'='1", "1 AND 1=1--"]
SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"SQLite.*Error",
    r"Microsoft OLE DB",
    r"Unclosed quotation mark",
    r"syntax error.*sql",
    r"Warning.*mysql",
    r"SQLSTATE\[",
    r"DB2 SQL error",
    r"quoted string not properly terminated",
]

# ── Open Redirect Probes ─────────────────────────────────────────────────────
REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_to", "return", "return_url",
                   "goto", "dest", "destination", "redir", "continue", "target", "from"]
REDIRECT_PAYLOAD = "https://evil.rlm-test-redirect.com"

# ── Sensitive Paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ("/.env", "CRITICAL", "Exposed .env File", "Environment file with credentials is publicly accessible."),
    ("/.git/config", "CRITICAL", "Exposed .git Directory", "Git configuration file is publicly accessible — may expose credentials and repo structure."),
    ("/.git/HEAD", "CRITICAL", "Exposed Git Repository", "Git HEAD file accessible — full source code may be downloadable."),
    ("/admin", "MEDIUM", "Admin Panel Accessible", "Admin panel is accessible. Verify authentication is required."),
    ("/admin/", "MEDIUM", "Admin Panel Accessible", "Admin panel is accessible."),
    ("/phpinfo.php", "HIGH", "phpinfo() Page Exposed", "PHP configuration details exposed including file paths, modules, and environment variables."),
    ("/server-status", "MEDIUM", "Apache Server Status Exposed", "Apache server-status shows active connections, request URIs, and performance data."),
    ("/server-info", "MEDIUM", "Apache Server Info Exposed", "Apache server-info reveals configuration details."),
    ("/.well-known/security.txt", "INFO", "security.txt Found", "Security contact file present — good practice."),
    ("/robots.txt", "INFO", "robots.txt Found", "Robots.txt may reveal hidden paths."),
    ("/sitemap.xml", "INFO", "Sitemap Found", "Sitemap discovered."),
    ("/backup.zip", "CRITICAL", "Backup Archive Exposed", "Backup archive potentially accessible."),
    ("/backup.sql", "CRITICAL", "SQL Backup Exposed", "SQL backup file potentially accessible."),
    ("/.DS_Store", "MEDIUM", "macOS .DS_Store File Exposed", ".DS_Store reveals directory structure."),
    ("/config.php", "HIGH", "Config File Exposed", "PHP config file may contain database credentials."),
    ("/wp-config.php", "CRITICAL", "WordPress Config Exposed", "WordPress configuration with database credentials."),
    ("/web.config", "HIGH", "ASP.NET Web Config Exposed", "Web.config may contain connection strings and secrets."),
    ("/swagger.json", "LOW", "API Documentation Exposed", "Swagger/OpenAPI spec publicly accessible — may reveal all endpoints."),
    ("/api/swagger.json", "LOW", "API Documentation Exposed", "Swagger API documentation accessible."),
    ("/api-docs", "LOW", "API Documentation Exposed", "API documentation endpoint accessible."),
    ("/actuator", "HIGH", "Spring Actuator Exposed", "Spring Boot Actuator endpoints may expose sensitive application internals."),
    ("/actuator/env", "CRITICAL", "Spring Actuator /env Exposed", "Environment variables including secrets may be accessible."),
    ("/debug", "HIGH", "Debug Endpoint Exposed", "Debug endpoint may expose sensitive application information."),
    ("/console", "CRITICAL", "Web Console Exposed", "Interactive console may be publicly accessible."),
    ("/metrics", "LOW", "Metrics Endpoint Exposed", "Application metrics exposed publicly."),
    ("/health", "INFO", "Health Check Endpoint", "Health check endpoint is publicly accessible."),
    ("/api/v1/users", "MEDIUM", "User API Endpoint Found", "User listing API endpoint — verify authentication required."),
    ("/.htpasswd", "CRITICAL", "Exposed .htpasswd File", "Apache password file is publicly accessible."),
    ("/.htaccess", "MEDIUM", "Exposed .htaccess File", "Apache configuration file is accessible."),
]


class ActiveProber:
    """Runs active security probes against discovered endpoints."""

    def __init__(self, session: requests.Session, timeout: int = 8, delay_ms: int = 100):
        self.session = session
        self.timeout = timeout
        self.delay_ms = delay_ms

    def probe_all(self, pages: List[CrawlResult], base_url: str) -> List[ProbeFinding]:
        findings: List[ProbeFinding] = []

        # 1. Sensitive path discovery
        findings.extend(self._check_sensitive_paths(base_url))

        for page in pages:
            # 2. Reflected XSS in URL params
            findings.extend(self._probe_xss_params(page))

            # 3. SQL injection in URL params
            findings.extend(self._probe_sqli_params(page))

            # 4. Open redirect in redirect-like params
            findings.extend(self._probe_open_redirect(page))

            # 5. CSRF check on forms
            findings.extend(self._check_csrf(page))

            # 6. Cookie security
            findings.extend(self._check_cookies(page))

        return findings

    def _check_sensitive_paths(self, base_url: str) -> List[ProbeFinding]:
        findings = []
        for path, severity, title, desc in SENSITIVE_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False, verify=False)
                if resp.status_code in (200, 206):
                    body_preview = resp.text[:200] if resp.text else ""
                    # For .env, check if it looks like env file
                    if path == "/.env" and "=" not in body_preview:
                        continue
                    findings.append(ProbeFinding(
                        check=f"SENSITIVE_PATH_{path.strip('/').upper().replace('.', '_')}",
                        severity=severity,
                        title=title,
                        url=url,
                        param="path",
                        payload=path,
                        description=desc,
                        recommendation=f"Restrict access to {path} via server configuration. Add authentication or block with firewall rules.",
                        evidence=f"HTTP {resp.status_code}: {body_preview[:100]}",
                    ))
                time.sleep(self.delay_ms / 1000)
            except Exception:
                continue
        return findings

    def _probe_xss_params(self, page: CrawlResult) -> List[ProbeFinding]:
        findings = []
        parsed = urlparse(page.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        for param_name in params:
            for payload, pattern in XSS_PROBES[:2]:  # limit probes
                try:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    new_query = urlencode({k: v[0] for k, v in test_params.items()})
                    test_url = parsed._replace(query=new_query).geturl()

                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append(ProbeFinding(
                            check="REFLECTED_XSS",
                            severity="HIGH",
                            title=f"Reflected XSS in Parameter '{param_name}'",
                            url=page.url,
                            param=param_name,
                            payload=payload,
                            description=f"The parameter '{param_name}' reflects user input unsanitized into the HTML response. This allows attackers to inject and execute JavaScript in victims' browsers.",
                            recommendation="Encode all user output. Use Content-Security-Policy. Apply context-aware escaping.",
                            evidence=f"Payload reflected at: {test_url}",
                        ))
                        break  # One finding per param is enough
                    time.sleep(self.delay_ms / 1000)
                except Exception:
                    continue
        return findings

    def _probe_sqli_params(self, page: CrawlResult) -> List[ProbeFinding]:
        findings = []
        parsed = urlparse(page.url)
        params = parse_qs(parsed.query)
        if not params:
            return []

        sqli_patterns = [re.compile(p, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS]

        for param_name in params:
            for probe in SQLI_PROBES[:2]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = [probe]
                    new_query = urlencode({k: v[0] for k, v in test_params.items()})
                    test_url = parsed._replace(query=new_query).geturl()

                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                    for pat in sqli_patterns:
                        if pat.search(resp.text):
                            findings.append(ProbeFinding(
                                check="SQL_INJECTION_ERROR",
                                severity="CRITICAL",
                                title=f"SQL Injection Error in Parameter '{param_name}'",
                                url=page.url,
                                param=param_name,
                                payload=probe,
                                description=f"SQL error triggered by injecting '{probe}' into '{param_name}'. Database error messages confirm SQL injection vulnerability.",
                                recommendation="Use parameterized queries. Never concatenate user input into SQL. Suppress database error messages in responses.",
                                evidence=f"DB error pattern found with payload: {probe}",
                            ))
                            break
                    time.sleep(self.delay_ms / 1000)
                except Exception:
                    continue
        return findings

    def _probe_open_redirect(self, page: CrawlResult) -> List[ProbeFinding]:
        findings = []
        parsed = urlparse(page.url)
        params = parse_qs(parsed.query)

        for param_name in params:
            if param_name.lower() not in REDIRECT_PARAMS:
                continue
            try:
                test_params = dict(params)
                test_params[param_name] = [REDIRECT_PAYLOAD]
                new_query = urlencode({k: v[0] for k, v in test_params.items()})
                test_url = parsed._replace(query=new_query).geturl()

                resp = self.session.get(test_url, timeout=self.timeout,
                                        allow_redirects=False, verify=False)
                location = resp.headers.get("Location", "")
                if REDIRECT_PAYLOAD in location or "evil.rlm-test-redirect" in location:
                    findings.append(ProbeFinding(
                        check="OPEN_REDIRECT",
                        severity="MEDIUM",
                        title=f"Open Redirect via Parameter '{param_name}'",
                        url=page.url,
                        param=param_name,
                        payload=REDIRECT_PAYLOAD,
                        description=f"The '{param_name}' parameter redirects to arbitrary external URLs without validation. Attackers use this for phishing: send users to your domain, they get redirected to a malicious site.",
                        recommendation="Validate redirect URLs against an allowlist. Only allow relative paths or known domains.",
                        evidence=f"Redirected to: {location}",
                    ))
                time.sleep(self.delay_ms / 1000)
            except Exception:
                continue
        return findings

    def _check_csrf(self, page: CrawlResult) -> List[ProbeFinding]:
        findings = []
        for form in page.forms:
            if form["method"] == "POST" and not form["has_csrf"]:
                has_state_inputs = any(
                    inp["type"] not in ("hidden", "submit", "button")
                    for inp in form["inputs"]
                )
                if has_state_inputs:
                    findings.append(ProbeFinding(
                        check="CSRF_MISSING_TOKEN",
                        severity="MEDIUM",
                        title="CSRF Token Missing in POST Form",
                        url=page.url,
                        param="form",
                        payload=form["action"],
                        description=f"A POST form at {form['action']} has no CSRF token. Attackers can trick logged-in users into submitting this form from another website.",
                        recommendation="Add a CSRF token to all state-changing forms. Use SameSite=Strict on session cookies.",
                        evidence=f"Form inputs: {[i['name'] for i in form['inputs']]}",
                    ))
        return findings

    def _check_cookies(self, page: CrawlResult) -> List[ProbeFinding]:
        findings = []
        set_cookie = page.headers.get("Set-Cookie", "") or page.headers.get("set-cookie", "")
        if not set_cookie:
            return []

        cookies = set_cookie.split(",")
        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            is_session = any(s in cookie_name.lower() for s in
                            ["session", "sid", "sess", "auth", "token", "jwt"])

            if "secure" not in cookie_lower and is_session:
                findings.append(ProbeFinding(
                    check="COOKIE_NO_SECURE",
                    severity="HIGH",
                    title=f"Session Cookie Missing 'Secure' Flag: {cookie_name}",
                    url=page.url,
                    param="Set-Cookie",
                    payload=cookie_name,
                    description="Session cookie without Secure flag can be transmitted over HTTP. If the site has any HTTP pages or an HTTP redirect, the cookie can be intercepted.",
                    recommendation="Set the Secure flag on all cookies: Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
                    evidence=cookie[:100],
                ))

            if "httponly" not in cookie_lower and is_session:
                findings.append(ProbeFinding(
                    check="COOKIE_NO_HTTPONLY",
                    severity="MEDIUM",
                    title=f"Session Cookie Missing 'HttpOnly' Flag: {cookie_name}",
                    url=page.url,
                    param="Set-Cookie",
                    payload=cookie_name,
                    description="Without HttpOnly, JavaScript can read the cookie via document.cookie. XSS becomes session hijacking.",
                    recommendation="Add HttpOnly flag to all session cookies.",
                    evidence=cookie[:100],
                ))

            if "samesite" not in cookie_lower and is_session:
                findings.append(ProbeFinding(
                    check="COOKIE_NO_SAMESITE",
                    severity="MEDIUM",
                    title=f"Session Cookie Missing 'SameSite' Flag: {cookie_name}",
                    url=page.url,
                    param="Set-Cookie",
                    payload=cookie_name,
                    description="Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks.",
                    recommendation="Add SameSite=Strict or SameSite=Lax to all session cookies.",
                    evidence=cookie[:100],
                ))

        return findings
