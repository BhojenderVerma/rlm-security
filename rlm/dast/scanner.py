"""
DAST Scanner Orchestrator — coordinates crawl, header checks, active probes, and SSL checks.
Converts all findings into the standard Finding model for unified reporting.
"""
from __future__ import annotations
import uuid
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from ..models import Report, Finding, CodeLocation, ScanSummary, FileScanResult
from .crawler import WebCrawler, CrawlResult
from .header_checks import check_security_headers, HeaderFinding
from .active_probes import ActiveProber, ProbeFinding
from .ssl_checks import check_ssl, SSLFinding


class DastScanner:
    """
    Full DAST scanner. Given a website URL:
    1. Crawls the site to discover pages/forms
    2. Checks HTTP security headers on each page
    3. Checks SSL/TLS configuration
    4. Runs active probes (XSS, SQLi, open redirect, sensitive paths, cookies, CSRF)
    5. Returns a unified Report object
    """

    def __init__(
        self,
        url: str,
        max_pages: int = 30,
        max_depth: int = 3,
        delay_ms: int = 300,
        timeout: int = 10,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        ignore_robots: bool = False,
    ):
        self.url = url.rstrip("/")
        parsed = urlparse(url)
        self.hostname = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_https = parsed.scheme == "https"

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "RLM-Security-Scanner/1.0 (security audit)",
            **(headers or {}),
        })
        if cookies:
            self.session.cookies.update(cookies)

        self.crawler = WebCrawler(
            base_url=url,
            max_pages=max_pages,
            max_depth=max_depth,
            delay_ms=delay_ms,
            timeout=timeout,
            headers=headers,
            cookies=cookies,
            ignore_robots=ignore_robots,
        )
        self.prober = ActiveProber(self.session, timeout=timeout, delay_ms=delay_ms)

    def scan(self, progress_callback=None) -> Report:
        """Run the full DAST scan and return a Report."""
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.utcnow()
        all_findings: List[Finding] = []
        pages_scanned = 0

        def _log(msg: str):
            if progress_callback:
                progress_callback(msg)

        # ── 1. SSL/TLS ───────────────────────────────────────────────────────
        _log("Checking SSL/TLS configuration...")
        if self.is_https:
            ssl_results = check_ssl(self.hostname, self.port)
            for sf in ssl_results:
                all_findings.append(self._ssl_to_finding(sf, scan_id))

        # ── 2. Crawl ─────────────────────────────────────────────────────────
        _log(f"Crawling {self.url} ...")
        pages: List[CrawlResult] = self.crawler.crawl()
        pages_scanned = len(pages)
        _log(f"Discovered {pages_scanned} pages")

        # ── 3. Security headers (per page, deduplicated by check type) ───────
        _log("Analyzing security headers...")
        seen_header_checks = set()
        for page in pages:
            header_findings = check_security_headers(page.url, page.headers)
            for hf in header_findings:
                key = hf.check
                if key not in seen_header_checks:
                    seen_header_checks.add(key)
                    all_findings.append(self._header_to_finding(hf, page.url, scan_id))

        # ── 4. Active probes ─────────────────────────────────────────────────
        _log("Running active security probes...")
        probe_findings = self.prober.probe_all(pages, self.url)
        for pf in probe_findings:
            all_findings.append(self._probe_to_finding(pf, scan_id))

        # ── Build report ─────────────────────────────────────────────────────
        by_sev = {}
        for f in all_findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        from collections import Counter
        by_cat = Counter(f.category for f in all_findings)
        total = len(all_findings)
        files_with_issues = pages_scanned  # treat each page as a "file"

        # Risk score: weighted sum
        risk = min(100, round(
            by_sev.get("CRITICAL", 0) * 15 +
            by_sev.get("HIGH", 0) * 8 +
            by_sev.get("MEDIUM", 0) * 4 +
            by_sev.get("LOW", 0) * 1
        ))

        summary = ScanSummary(
            total_files=pages_scanned,
            files_with_issues=files_with_issues,
            total_findings=total,
            risk_score=float(risk),
            by_severity={k: v for k, v in by_sev.items()},
            by_category=dict(by_cat),
        )

        # Build synthetic FileScanResult per page
        page_results: List[FileScanResult] = []
        page_findings_map = {}
        for f in all_findings:
            page_findings_map.setdefault(f.location.file, []).append(f)

        for page in pages:
            page_path = urlparse(page.url).path or "/"
            page_results.append(FileScanResult(
                file_path=page.url,
                language="html",
                lines_analyzed=len(page.body.splitlines()),
                findings=page_findings_map.get(page.url, []),
                scan_duration_ms=page.response_time_ms,
            ))

        elapsed = (datetime.utcnow() - start_time).total_seconds()

        return Report(
            scan_id=f"dast-{scan_id}",
            source=self.url,
            source_type="url",
            timestamp=start_time,
            summary=summary,
            file_results=page_results,
            metadata={
                "scan_duration_seconds": round(elapsed, 2),
                "pages_crawled": pages_scanned,
                "scan_type": "DAST",
                "target": self.url,
            },
        )

    # ── Conversion helpers ───────────────────────────────────────────────────

    def _header_to_finding(self, hf: HeaderFinding, url: str, scan_id: str) -> Finding:
        sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO", "CRITICAL": "CRITICAL"}
        cat_map = {
            "CSP": "XSS", "XFO": "XSS", "CORS": "XSS",
            "HSTS": "OTHER", "XCTO": "OTHER", "RP": "OTHER",
            "PP": "OTHER", "SERVER": "OTHER", "XPOWERED": "OTHER",
        }
        prefix = hf.check.split("_")[0]
        return Finding(
            id=str(uuid.uuid4())[:8],
            title=hf.title,
            description=hf.description,
            severity=sev_map.get(hf.severity, "MEDIUM"),
            category=cat_map.get(prefix, "OTHER"),
            location=CodeLocation(file=url, line_start=0, line_end=0),
            code_snippet=f"Response header: {hf.actual}" if hf.actual else "(header not present)",
            recommendation=hf.recommendation,
            confidence="HIGH",
            references=[],
            cwe_id=None,
        )

    def _ssl_to_finding(self, sf: SSLFinding, scan_id: str) -> Finding:
        return Finding(
            id=str(uuid.uuid4())[:8],
            title=sf.title,
            description=sf.description,
            severity=sf.severity,
            category="CRYPTO_MISUSE",
            location=CodeLocation(file=self.url, line_start=0, line_end=0),
            code_snippet=sf.evidence or "(SSL/TLS layer)",
            recommendation=sf.recommendation,
            confidence="HIGH",
            references=[],
            cwe_id=None,
        )

    def _probe_to_finding(self, pf: ProbeFinding, scan_id: str) -> Finding:
        cat_map = {
            "REFLECTED_XSS": "XSS",
            "SQL_INJECTION_ERROR": "SQL_INJECTION",
            "OPEN_REDIRECT": "OTHER",
            "CSRF_MISSING_TOKEN": "OTHER",
            "COOKIE_NO_SECURE": "OTHER",
            "COOKIE_NO_HTTPONLY": "OTHER",
            "COOKIE_NO_SAMESITE": "OTHER",
        }
        if pf.check.startswith("SENSITIVE_PATH"):
            cat = "HARDCODED_SECRET"
        else:
            cat = cat_map.get(pf.check, "OTHER")

        return Finding(
            id=str(uuid.uuid4())[:8],
            title=pf.title,
            description=pf.description,
            severity=pf.severity,
            category=cat,
            location=CodeLocation(file=pf.url, line_start=0, line_end=0),
            code_snippet=f"Parameter: {pf.param}\nPayload: {pf.payload}\nEvidence: {pf.evidence}",
            recommendation=pf.recommendation,
            confidence="HIGH",
            references=[],
            cwe_id=None,
        )
