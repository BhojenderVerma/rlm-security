"""
Shared Analysis Context — thread-safe shared state for the RLM scan session.
"""

from __future__ import annotations
import threading
from typing import List, Optional
from ..models import FileScanResult


class ScanContext:
    """Thread-safe shared context for a scan session."""

    def __init__(self, source: str, source_type: str, llm_model: str = "gemini-2.0-flash"):
        self.source = source
        self.source_type = source_type
        self.llm_model = llm_model
        self._results: List[FileScanResult] = []
        self._lock = threading.Lock()

    def add_result(self, result: FileScanResult) -> None:
        with self._lock:
            self._results.append(result)

    @property
    def results(self) -> List[FileScanResult]:
        with self._lock:
            return list(self._results)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)
