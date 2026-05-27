"""
Root RLM Agent — the main orchestrator.
Spawns Sub-LLM agents per file using a thread pool and aggregates results.
"""

from __future__ import annotations
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Callable
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from .context import ScanContext
from .sub_agent import SubAgent
from ..models import Report, FileScanResult, ScanSummary, Finding

console = Console()


class RootAgent:
    """
    Root RLM Orchestrator.
    Manages parallel file scanning, aggregates findings, and builds the final Report.
    """

    def __init__(
        self,
        max_workers: int = 8,
        llm_client=None,
        on_file_done: Optional[Callable[[FileScanResult], None]] = None,
    ):
        self.max_workers = max_workers
        self.llm_client = llm_client
        self.on_file_done = on_file_done

    def scan(
        self,
        files: List[Tuple[str, str]],
        source: str,
        source_type: str,
    ) -> Report:
        """
        Run the full recursive analysis.

        Args:
            files: List of (file_path, content) tuples
            source: Human-readable source description
            source_type: 'github' | 'local' | 'zip'

        Returns:
            Complete Report object
        """
        ctx = ScanContext(source=source, source_type=source_type)
        scan_start = time.time()

        console.rule("[bold cyan]🔍 RLM Security Analysis")
        console.print(f"  [bold]Source:[/bold] {source}")
        console.print(f"  [bold]Files:[/bold] {len(files)}")
        console.print(f"  [bold]Workers:[/bold] {self.max_workers}")
        console.print()

        results: List[FileScanResult] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Scanning files...", total=len(files))

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all file scan jobs
                future_to_file = {
                    executor.submit(self._scan_one, file_path, content): file_path
                    for file_path, content in files
                }

                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        results.append(result)
                        ctx.add_result(result)

                        if self.on_file_done:
                            self.on_file_done(result)

                        # Update progress description with latest file
                        basename = os.path.basename(file_path)
                        findings_count = len(result.findings)
                        color = "red" if findings_count > 0 else "green"
                        progress.update(
                            task,
                            advance=1,
                            description=f"[cyan]Scanning:[/cyan] [{color}]{basename}[/{color}] "
                                        f"({findings_count} findings)",
                        )
                    except Exception as exc:
                        results.append(
                            FileScanResult(
                                file_path=file_path,
                                language="unknown",
                                lines_analyzed=0,
                                findings=[],
                                error=str(exc),
                            )
                        )
                        progress.advance(task)

        scan_duration = time.time() - scan_start

        # Build summary
        summary = self._build_summary(results)

        report = Report(
            source=source,
            source_type=source_type,
            file_results=results,
            summary=summary,
            metadata={
                "scan_duration_seconds": round(scan_duration, 2),
                "max_workers": self.max_workers,
                "analyzer_count": 6,
            },
        )

        self._print_summary(report)
        return report

    def _scan_one(self, file_path: str, content: str) -> FileScanResult:
        """Worker function — creates a fresh SubAgent and scans one file."""
        agent = SubAgent(llm_client=self.llm_client)
        return agent.scan_file(file_path, content)

    def _build_summary(self, results: List[FileScanResult]) -> ScanSummary:
        """Aggregate all findings into a summary."""
        all_findings: List[Finding] = []
        for r in results:
            all_findings.extend(r.findings)

        by_severity: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_category: dict = {}

        for f in all_findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1

        files_with_issues = sum(1 for r in results if r.findings)

        # Risk score: weighted sum normalized to 100
        risk_score = min(
            100.0,
            (by_severity["CRITICAL"] * 10 + by_severity["HIGH"] * 5 +
             by_severity["MEDIUM"] * 2 + by_severity["LOW"] * 0.5),
        )

        return ScanSummary(
            total_files=len(results),
            files_with_issues=files_with_issues,
            total_findings=len(all_findings),
            by_severity=by_severity,
            by_category=by_category,
            risk_score=round(risk_score, 1),
        )

    def _print_summary(self, report: Report) -> None:
        """Print a rich terminal summary table."""
        s = report.summary
        console.print()
        console.rule("[bold yellow]📊 Scan Complete")

        table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 2))
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Files Scanned", str(s.total_files))
        table.add_row("Files with Issues", f"[yellow]{s.files_with_issues}[/yellow]")
        table.add_row("Total Findings", f"[bold]{s.total_findings}[/bold]")
        table.add_row("🔴 Critical", f"[bold red]{s.by_severity.get('CRITICAL', 0)}[/bold red]")
        table.add_row("🟠 High", f"[red]{s.by_severity.get('HIGH', 0)}[/red]")
        table.add_row("🟡 Medium", f"[yellow]{s.by_severity.get('MEDIUM', 0)}[/yellow]")
        table.add_row("🟢 Low", f"[green]{s.by_severity.get('LOW', 0)}[/green]")
        table.add_row("Risk Score", f"[bold magenta]{s.risk_score}/100[/bold magenta]")

        console.print(table)
        console.print()
