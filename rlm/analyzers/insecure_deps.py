"""
Insecure Dependencies Detector.
Parses requirements.txt, package.json, Pipfile, etc.
and checks for known vulnerable packages.
"""

from __future__ import annotations
import re
import json
from typing import List, Dict, Tuple, Optional
from .base import BaseAnalyzer
from ..models import Finding, CodeLocation


# ── Known vulnerable package registry ───────────────────────────────────────
# Format: package_name → list of (max_version, severity, cve, description, recommendation)
# Version comparison is approximate (string-based) — use Safety/Snyk for production.

PYTHON_VULNS: Dict[str, List[Tuple]] = {
    "django": [
        ("2.2.27", "HIGH", "CVE-2021-35042", "SQL injection in Django QuerySet.order_by()", "Upgrade to Django ≥ 3.2.13"),
        ("3.2.12", "HIGH", "CVE-2022-28346", "SQL injection via QuerySet.annotate()", "Upgrade to Django ≥ 3.2.13"),
    ],
    "flask": [
        ("0.12.5", "MEDIUM", "CVE-2018-1000656", "Denial of service via crafted JSON", "Upgrade to Flask ≥ 1.0"),
    ],
    "requests": [
        ("2.19.1", "HIGH", "CVE-2018-18074", "Credentials leak via redirect", "Upgrade to requests ≥ 2.20.0"),
    ],
    "pillow": [
        ("9.0.1", "HIGH", "CVE-2022-22816", "Buffer overflow in path_getbbox()", "Upgrade to Pillow ≥ 9.0.1"),
    ],
    "pyyaml": [
        ("5.4.1", "CRITICAL", "CVE-2020-14343", "Arbitrary code execution via yaml.load()", "Use yaml.safe_load() and upgrade to PyYAML ≥ 6.0"),
    ],
    "cryptography": [
        ("41.0.0", "HIGH", "CVE-2023-49083", "NULL pointer dereference in PKCS12", "Upgrade to cryptography ≥ 41.0.6"),
    ],
    "paramiko": [
        ("2.9.3", "HIGH", "CVE-2022-24302", "Race condition in key file creation", "Upgrade to paramiko ≥ 2.9.4"),
    ],
    "urllib3": [
        ("1.26.14", "HIGH", "CVE-2023-43804", "Cookie header injection", "Upgrade to urllib3 ≥ 1.26.17 or ≥ 2.0.6"),
    ],
}

NPM_VULNS: Dict[str, List[Tuple]] = {
    "lodash": [
        ("4.17.20", "HIGH", "CVE-2021-23337", "Command injection via template()", "Upgrade to lodash ≥ 4.17.21"),
    ],
    "axios": [
        ("0.21.1", "HIGH", "CVE-2021-3749", "Denial of service via crafted SSRF", "Upgrade to axios ≥ 0.21.2"),
    ],
    "express": [
        ("4.16.0", "MEDIUM", "CVE-2022-24999", "Open redirect vulnerability", "Upgrade to express ≥ 4.18.2"),
    ],
    "jsonwebtoken": [
        ("8.5.1", "CRITICAL", "CVE-2022-23529", "Private key injection in jwt.verify()", "Upgrade to jsonwebtoken ≥ 9.0.0"),
    ],
    "node-fetch": [
        ("2.6.6", "HIGH", "CVE-2022-0235", "Exposure of sensitive information via redirect", "Upgrade to node-fetch ≥ 2.6.7 or ≥ 3.1.1"),
    ],
    "minimist": [
        ("1.2.5", "CRITICAL", "CVE-2021-44906", "Prototype pollution", "Upgrade to minimist ≥ 1.2.6"),
    ],
    "moment": [
        ("2.29.3", "HIGH", "CVE-2022-31129", "ReDoS in parseZone()", "Upgrade to moment ≥ 2.29.4 or migrate to date-fns/Day.js"),
    ],
}


def _version_le(v1: str, v2: str) -> bool:
    """Very simple version comparison: returns True if v1 <= v2."""
    try:
        parts1 = [int(x) for x in re.split(r'[.\-]', v1)[:3]]
        parts2 = [int(x) for x in re.split(r'[.\-]', v2)[:3]]
        return parts1 <= parts2
    except Exception:
        return False


def _parse_requirements_txt(content: str) -> Dict[str, str]:
    """Parse requirements.txt → {package: version}."""
    deps: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[=<>!~]{1,2}\s*([0-9][^\s,;]*)', line)
        if m:
            deps[m.group(1).lower()] = m.group(2)
    return deps


def _parse_package_json(content: str) -> Dict[str, str]:
    """Parse package.json → {package: version}."""
    deps: Dict[str, str] = {}
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies"):
            for pkg, ver in data.get(section, {}).items():
                ver_clean = re.sub(r'[\^~>=<]', '', ver).strip()
                deps[pkg.lower()] = ver_clean
    except Exception:
        pass
    return deps


class InsecureDepsAnalyzer(BaseAnalyzer):
    name = "InsecureDepsAnalyzer"
    category = "INSECURE_DEPENDENCY"

    MANIFEST_FILES = {
        "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
        "Pipfile", "package.json",
    }

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        findings: List[Finding] = []
        basename = file_path.split("/")[-1].split("\\")[-1]

        if basename not in self.MANIFEST_FILES:
            return []

        if basename == "package.json":
            deps = _parse_package_json(content)
            vuln_db = NPM_VULNS
        else:
            deps = _parse_requirements_txt(content)
            vuln_db = PYTHON_VULNS

        lines = content.splitlines()

        for pkg, installed_ver in deps.items():
            if pkg in vuln_db:
                for (max_ver, severity, cve, desc, rec) in vuln_db[pkg]:
                    if _version_le(installed_ver, max_ver):
                        # Find approximate line in file
                        line_num = 1
                        for i, ln in enumerate(lines):
                            if re.search(re.escape(pkg), ln, re.IGNORECASE):
                                line_num = i + 1
                                break

                        findings.append(
                            Finding(
                                location=CodeLocation(
                                    file=file_path,
                                    line_start=line_num,
                                    line_end=line_num,
                                ),
                                severity=severity,
                                category=self.category,
                                title=f"Vulnerable Dependency: {pkg} ({installed_ver})",
                                description=f"{desc} [{cve}]",
                                code_snippet=self._get_snippet(lines, line_num - 1),
                                recommendation=rec,
                                cwe_id="CWE-1395",
                                confidence="HIGH",
                                references=[
                                    f"https://nvd.nist.gov/vuln/detail/{cve}",
                                    f"https://osv.dev/vulnerability/{cve}",
                                ],
                            )
                        )

        return findings
