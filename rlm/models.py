"""
RLM Security Analysis System
Pydantic data models for findings, reports, and scan metadata.
"""

from __future__ import annotations
from datetime import datetime
from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field
import uuid


SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CategoryType = Literal[
    "SQL_INJECTION",
    "XSS",
    "HARDCODED_SECRET",
    "PATH_TRAVERSAL",
    "INSECURE_DEPENDENCY",
    "CRYPTO_MISUSE",
    "OTHER",
]


class CodeLocation(BaseModel):
    """Precise location of a finding in source code."""
    file: str
    line_start: int
    line_end: int
    column: Optional[int] = None


class Finding(BaseModel):
    """A single security vulnerability finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    location: CodeLocation
    severity: SeverityLevel
    category: CategoryType
    title: str
    description: str
    code_snippet: str
    recommendation: str
    cwe_id: Optional[str] = None
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "MEDIUM"
    references: List[str] = Field(default_factory=list)


class FileScanResult(BaseModel):
    """Result of scanning a single file."""
    file_path: str
    language: str
    lines_analyzed: int
    findings: List[Finding] = Field(default_factory=list)
    scan_duration_ms: float = 0.0
    error: Optional[str] = None


class ScanSummary(BaseModel):
    """Aggregated statistics for the entire scan."""
    total_files: int
    files_with_issues: int
    total_findings: int
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    risk_score: float = 0.0  # 0-100


class Report(BaseModel):
    """Full security analysis report."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str  # GitHub URL, local path, or zip filename
    source_type: Literal["github", "local", "zip", "url"]
    file_results: List[FileScanResult] = Field(default_factory=list)
    summary: ScanSummary
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def all_findings(self) -> List[Finding]:
        findings = []
        for result in self.file_results:
            findings.extend(result.findings)
        return findings

    @property
    def critical_findings(self) -> List[Finding]:
        return [f for f in self.all_findings if f.severity == "CRITICAL"]

    @property
    def high_findings(self) -> List[Finding]:
        return [f for f in self.all_findings if f.severity == "HIGH"]
