"""
JSON Report Generator — serializes the Report model to structured JSON.
"""

from __future__ import annotations
import json
import os
from datetime import datetime
from ..models import Report


def generate_json(report: Report, output_path: str) -> str:
    """
    Write the full report to a JSON file.

    Args:
        report: The Report object
        output_path: File path to write the JSON to

    Returns:
        Absolute path of the written file
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Build the JSON structure
    data = {
        "scan_id": report.scan_id,
        "timestamp": report.timestamp.isoformat() + "Z",
        "source": report.source,
        "source_type": report.source_type,
        "summary": {
            "total_files": report.summary.total_files,
            "files_with_issues": report.summary.files_with_issues,
            "total_findings": report.summary.total_findings,
            "risk_score": report.summary.risk_score,
            "by_severity": report.summary.by_severity,
            "by_category": report.summary.by_category,
        },
        "findings": [],
        "files": [],
        "metadata": report.metadata,
    }

    # Flat findings list (sorted by severity)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings = sorted(
        report.all_findings,
        key=lambda f: severity_order.get(f.severity, 9),
    )
    data["findings"] = [
        {
            "id": f.id,
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "description": f.description,
            "file": f.location.file,
            "line_start": f.location.line_start,
            "line_end": f.location.line_end,
            "code_snippet": f.code_snippet,
            "recommendation": f.recommendation,
            "cwe_id": f.cwe_id,
            "confidence": f.confidence,
            "references": f.references,
        }
        for f in all_findings
    ]

    # Per-file breakdown
    data["files"] = [
        {
            "path": r.file_path,
            "language": r.language,
            "lines_analyzed": r.lines_analyzed,
            "finding_count": len(r.findings),
            "scan_duration_ms": r.scan_duration_ms,
            "error": r.error,
        }
        for r in sorted(report.file_results, key=lambda r: -len(r.findings))
    ]

    output_path = os.path.abspath(output_path)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    return output_path
