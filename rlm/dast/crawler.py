"""
Web Crawler — BFS spider that discovers URLs for DAST scanning.
Respects robots.txt, rate limits, and max-depth settings.
"""
from __future__ import annotations
import re
import time
from urllib.parse import urljoin, urlparse, urlencode
from typing import List, Set, Dict, Optional, Tuple
import requests
from requests.exceptions import RequestException

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class CrawlResult:
    """Single page result from the crawler."""
    def __init__(self, url: str, status: int, headers: dict,
                 body: str, content_type: str, response_time_ms: float,
                 forms: List[dict] = None):
        self.url = url
        self.status = status
        self.headers = headers
        self.body = body
        self.content_type = content_type
        self.response_time_ms = response_time_ms
        self.forms = forms or []
        self.links: List[str] = []
        self.params: Dict[str, str] = dict(urlparse(url).params or {})


class WebCrawler:
    """BFS web spider for DAST target discovery."""

    def __init__(
        self,
        base_url: str,
        max_pages: int = 50,
        max_depth: int = 3,
        delay_ms: int = 200,
        timeout: int = 10,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        ignore_robots: bool = False,
    ):
        parsed = urlparse(base_url)
        self.base_url = base_url.rstrip("/")
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay_ms = delay_ms
        self.timeout = timeout
        self.ignore_robots = ignore_robots

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "RLM-Security-Scanner/1.0 (security audit; contact: security@example.com)",
            **(headers or {}),
        })
        if cookies:
            self.session.cookies.update(cookies)

        self._visited: Set[str] = set()
        self._disallowed: Set[str] = set()

    def crawl(self) -> List[CrawlResult]:
        """Run BFS crawl starting from base_url."""
        if not self.ignore_robots:
            self._fetch_robots()

        queue: List[Tuple[str, int]] = [(self.base_url, 0)]
        results: List[CrawlResult] = []

        while queue and len(results) < self.max_pages:
            url, depth = queue.pop(0)
            url = self._normalize_url(url)

            if not url or url in self._visited:
                continue
            if depth > self.max_depth:
                continue
            if self._is_disallowed(url):
                continue

            self._visited.add(url)
            result = self._fetch(url)
            if result is None:
                continue

            results.append(result)

            # Discover links for next BFS level
            if depth < self.max_depth and "html" in result.content_type:
                for link in result.links:
                    normalized = self._normalize_url(link)
                    if normalized and normalized not in self._visited:
                        if self._is_same_domain(normalized):
                            queue.append((normalized, depth + 1))

            time.sleep(self.delay_ms / 1000.0)

        return results

    def _fetch(self, url: str) -> Optional[CrawlResult]:
        """Fetch a single URL and parse its links and forms."""
        try:
            start = time.time()
            resp = self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, verify=False)
            elapsed = (time.time() - start) * 1000

            content_type = resp.headers.get("Content-Type", "")
            body = resp.text if "html" in content_type or "json" in content_type else ""

            result = CrawlResult(
                url=resp.url,
                status=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                content_type=content_type,
                response_time_ms=round(elapsed, 1),
            )

            if BS4_AVAILABLE and "html" in content_type:
                result.links, result.forms = self._parse_html(resp.url, body)

            return result

        except RequestException:
            return None

    def _parse_html(self, base_url: str, html: str) -> Tuple[List[str], List[dict]]:
        """Extract links and forms from HTML."""
        soup = BeautifulSoup(html, "html.parser")

        # Extract links
        links = []
        for tag in soup.find_all(["a", "link", "script", "img", "iframe", "form"]):
            for attr in ["href", "src", "action"]:
                val = tag.get(attr, "")
                if val and not val.startswith(("#", "javascript:", "mailto:", "tel:")):
                    links.append(urljoin(base_url, val))

        # Extract forms
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type = inp.get("type", "text")
                inp_name = inp.get("name", "")
                if inp_name:
                    inputs.append({
                        "name": inp_name,
                        "type": inp_type,
                        "value": inp.get("value", ""),
                    })
            forms.append({
                "action": urljoin(base_url, form.get("action", base_url)),
                "method": form.get("method", "get").upper(),
                "inputs": inputs,
                "has_csrf": any("csrf" in i["name"].lower() or "token" in i["name"].lower()
                                for i in inputs),
            })

        return links, forms

    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize URL — strip fragments, sort params."""
        if not url:
            return None
        parsed = urlparse(url)
        # Only http/https
        if parsed.scheme not in ("http", "https"):
            return None
        # Strip fragment
        normalized = parsed._replace(fragment="").geturl()
        return normalized

    def _is_same_domain(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""

    def _is_disallowed(self, url: str) -> bool:
        path = urlparse(url).path
        return any(path.startswith(d) for d in self._disallowed)

    def _fetch_robots(self):
        """Fetch and parse robots.txt for disallowed paths."""
        robots_url = f"{self.base_scheme}://{self.base_domain}/robots.txt"
        try:
            resp = self.session.get(robots_url, timeout=5)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            self._disallowed.add(path)
        except Exception:
            pass
