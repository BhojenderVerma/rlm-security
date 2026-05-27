"""
Base Security Analyzer — abstract class all analyzers inherit from.
Each analyzer uses regex pattern matching + optional LLM reasoning.
"""

from __future__ import annotations
import re
import time
from abc import ABC, abstractmethod
from typing import List, Optional
from ..models import Finding, CodeLocation, SeverityLevel, CategoryType


class BaseAnalyzer(ABC):
    """Abstract base class for all security analyzers."""

    name: str = "BaseAnalyzer"
    category: CategoryType = "OTHER"

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    @abstractmethod
    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        """
        Analyze file content and return a list of findings.
        Args:
            file_path: Relative path to the file
            content: Full text content of the file
            language: Detected programming language
        Returns:
            List of Finding objects
        """
        ...

    # ──────────────────────────────────────────────
    # Shared helpers available to all subclasses
    # ──────────────────────────────────────────────

    def _get_snippet(self, lines: List[str], line_idx: int, context: int = 2) -> str:
        """Return a code snippet centred on line_idx (0-based)."""
        start = max(0, line_idx - context)
        end = min(len(lines), line_idx + context + 1)
        numbered = [
            f"{'→ ' if i == line_idx else '  '}{i + 1:4d} | {lines[i]}"
            for i in range(start, end)
        ]
        return "\n".join(numbered)

    def _scan_patterns(
        self,
        file_path: str,
        content: str,
        patterns: List[dict],
        severity: SeverityLevel,
    ) -> List[Finding]:
        """
        Generic pattern scanner used by multiple analyzers.
        Each pattern dict has keys: regex, title, description, recommendation, cwe_id (optional).
        """
        findings: List[Finding] = []
        lines = content.splitlines()

        for pat in patterns:
            regex = pat["regex"]
            for i, line in enumerate(lines):
                if re.search(regex, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            location=CodeLocation(
                                file=file_path,
                                line_start=i + 1,
                                line_end=i + 1,
                            ),
                            severity=severity,
                            category=self.category,
                            title=pat["title"],
                            description=pat["description"],
                            code_snippet=self._get_snippet(lines, i),
                            recommendation=pat["recommendation"],
                            cwe_id=pat.get("cwe_id"),
                            confidence=pat.get("confidence", "MEDIUM"),
                            references=pat.get("references", []),
                        )
                    )

        return findings
