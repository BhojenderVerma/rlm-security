"""
RLM Security Analysis System — CLI Entrypoint
Usage:
  python main.py scan --local ./myproject
  python main.py scan --github https://github.com/owner/repo
  python main.py scan --zip ./archive.zip --pdf --json
  python main.py scan --url https://example.com
  python main.py dashboard ./reports/report.json
"""

from __future__ import annotations
import os
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

app = typer.Typer(
    name="rlm",
    help="🔒 RLM Security Analysis System — Recursive LLM-based vulnerability scanner",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

BANNER = """[bold cyan]
██████╗ ██╗     ███╗   ███╗    [bold white]Security Analysis System[/bold white]
██╔══██╗██║     ████╗ ████║    [dim]Recursive LLM Vulnerability Scanner[/dim]
██████╔╝██║     ██╔████╔██║
██╔══██╗██║     ██║╚██╔╝██║    [dim]v2.0.0 — 16 Analyzers + DAST Engine[/dim]
██║  ██║███████╗██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
[/bold cyan]"""


# ── scan command ──────────────────────────────────────────────────────────────
@app.command()
def scan(
    local: Optional[str]    = typer.Option(None, "--local",  "-l", help="Path to local directory or file"),
    github: Optional[str]   = typer.Option(None, "--github", "-g", help="GitHub repository URL"),
    zip_file: Optional[str] = typer.Option(None, "--zip",    "-z", help="Path to ZIP archive"),
    url: Optional[str]      = typer.Option(None, "--url",    "-u", help="Website URL for DAST scan"),
    output_dir: str         = typer.Option("./reports", "--output", "-o", help="Output directory for reports"),
    json_out: bool          = typer.Option(True,  "--json/--no-json", help="Generate JSON report"),
    pdf_out: bool           = typer.Option(True,  "--pdf/--no-pdf",   help="Generate PDF report"),
    github_issues: bool     = typer.Option(False, "--issues",         help="Create real GitHub Issues"),
    repo: Optional[str]     = typer.Option(None,  "--repo",           help="GitHub repo (owner/repo) for issue creation"),
    token: Optional[str]    = typer.Option(None,  "--token",          help="GitHub personal access token"),
    workers: int            = typer.Option(8,     "--workers", "-w",  help="Parallel workers (static scan)"),
    min_severity: str       = typer.Option("MEDIUM", "--min-severity", help="Minimum severity for GitHub Issues"),
    # DAST-specific
    max_pages: int          = typer.Option(30,  "--max-pages",  help="Max pages to crawl (--url mode)"),
    max_depth: int          = typer.Option(3,   "--max-depth",  help="Crawler max depth (--url mode)"),
    delay_ms: int           = typer.Option(300, "--delay-ms",   help="Delay between requests in ms (--url mode)"),
    ignore_robots: bool     = typer.Option(False, "--ignore-robots", help="Ignore robots.txt (use responsibly)"),
):
    """
    🔍 Scan for security vulnerabilities.

    Input modes:\n
    [cyan]--local[/cyan]   Local directory or file (static analysis)\n
    [cyan]--github[/cyan]  GitHub repository URL  (static analysis)\n
    [cyan]--zip[/cyan]     ZIP archive            (static analysis)\n
    [cyan]--url[/cyan]     Live website URL       (DAST — dynamic testing)\n
    """
    console.print(BANNER)

    sources = [s for s in [local, github, zip_file, url] if s]
    if not sources:
        console.print("[bold red]Error:[/bold red] Specify one input: --local, --github, --zip, or --url")
        raise typer.Exit(1)
    if len(sources) > 1:
        console.print("[bold red]Error:[/bold red] Specify only one input source at a time")
        raise typer.Exit(1)

    report = None

    # ── URL / DAST mode ───────────────────────────────────────────────────────
    if url:
        report = _run_dast(url, max_pages, max_depth, delay_ms, ignore_robots)

    # ── Static scan mode ──────────────────────────────────────────────────────
    else:
        files = []
        source_label = ""
        source_type = ""

        with console.status("[cyan]Loading files...[/cyan]"):
            try:
                if local:
                    from rlm.input import load_local
                    files = load_local(local)
                    source_label = os.path.abspath(local)
                    source_type = "local"
                elif github:
                    from rlm.input import load_github
                    gh_token = token or os.environ.get("GITHUB_TOKEN")
                    files = load_github(github, token=gh_token)
                    source_label = github
                    source_type = "github"
                elif zip_file:
                    from rlm.input import load_zip
                    files = load_zip(zip_file)
                    source_label = zip_file
                    source_type = "zip"
            except Exception as exc:
                console.print(f"[bold red]Error loading files:[/bold red] {exc}")
                raise typer.Exit(1)

        if not files:
            console.print("[yellow]Warning:[/yellow] No analyzable files found.")
            raise typer.Exit(0)

        console.print(f"  [green]✓[/green] Loaded [bold]{len(files)}[/bold] files")

        from rlm.core import RootAgent
        agent = RootAgent(max_workers=workers)
        try:
            report = agent.scan(files, source=source_label, source_type=source_type)
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted.[/yellow]")
            raise typer.Exit(0)

    # ── Outputs ───────────────────────────────────────────────────────────────
    _generate_outputs(report, output_dir, json_out, pdf_out, github_issues, repo, token, min_severity)


def _run_dast(url: str, max_pages: int, max_depth: int, delay_ms: int, ignore_robots: bool):
    """Run DAST scan against a live website."""
    from rlm.dast.scanner import DastScanner

    console.print(f"  [bold cyan]🌐 DAST Mode:[/bold cyan] Scanning live website → [cyan]{url}[/cyan]")
    console.print(f"  Max pages: [bold]{max_pages}[/bold]  Depth: [bold]{max_depth}[/bold]  Delay: [bold]{delay_ms}ms[/bold]\n")

    scanner = DastScanner(
        url=url,
        max_pages=max_pages,
        max_depth=max_depth,
        delay_ms=delay_ms,
        ignore_robots=ignore_robots,
    )

    steps = [
        "Checking SSL/TLS configuration...",
        "Crawling website pages...",
        "Analyzing security headers...",
        "Running active probes (XSS, SQLi, open redirect)...",
        "Checking sensitive paths...",
        "Analyzing cookies and CSRF protection...",
        "Finalizing report...",
    ]

    step_idx = [0]
    report = [None]

    def _progress_cb(msg: str):
        console.print(f"  [dim]→[/dim] {msg}")

    with console.status("[cyan]DAST scanning...[/cyan]", spinner="dots"):
        try:
            report[0] = scanner.scan(progress_callback=_progress_cb)
        except KeyboardInterrupt:
            console.print("\n[yellow]DAST scan interrupted.[/yellow]")
            raise typer.Exit(0)
        except Exception as exc:
            console.print(f"[bold red]DAST scan error:[/bold red] {exc}")
            raise typer.Exit(1)

    return report[0]


def _generate_outputs(report, output_dir, json_out, pdf_out, github_issues, repo, token, min_severity):
    """Generate all requested output files and print summary."""
    os.makedirs(output_dir, exist_ok=True)
    safe_name = _safe_filename(report.source)
    timestamp = report.timestamp.strftime("%Y%m%d_%H%M%S")
    scan_type = "dast" if report.source_type == "url" else "rlm"
    base_name = f"{scan_type}_{safe_name}_{timestamp}"

    s = report.summary

    # Summary table
    from rich.table import Table
    table = Table(title="📊 Scan Complete", show_header=True, header_style="bold cyan",
                  border_style="cyan", min_width=40)
    table.add_column("Metric", style="dim", width=26)
    table.add_column("Value", justify="right", style="bold")

    label = "Pages Scanned" if report.source_type == "url" else "Files Scanned"
    table.add_row(label, str(s.total_files))
    table.add_row("Pages/Files w/ Issues", str(s.files_with_issues))
    table.add_row("Total Findings", str(s.total_findings))
    table.add_row("🔴 Critical", f"[red]{s.by_severity.get('CRITICAL', 0)}[/red]")
    table.add_row("🟠 High",     f"[orange1]{s.by_severity.get('HIGH', 0)}[/orange1]")
    table.add_row("🟡 Medium",   f"[yellow]{s.by_severity.get('MEDIUM', 0)}[/yellow]")
    table.add_row("🟢 Low",      f"[green]{s.by_severity.get('LOW', 0)}[/green]")
    table.add_row("🔵 Info",     f"[blue]{s.by_severity.get('INFO', 0)}[/blue]")
    table.add_row("Risk Score",  f"{s.risk_score}/100")
    console.print(table)

    if json_out:
        from rlm.output import generate_json
        json_path = os.path.join(output_dir, f"{base_name}.json")
        path = generate_json(report, json_path)
        console.print(f"  [green]✓[/green] JSON report: [cyan]{path}[/cyan]")

    if pdf_out:
        try:
            from rlm.output import generate_pdf
            pdf_path = os.path.join(output_dir, f"{base_name}.pdf")
            path = generate_pdf(report, pdf_path)
            console.print(f"  [green]✓[/green] PDF report:  [cyan]{path}[/cyan]")
        except ImportError:
            console.print("  [yellow]⚠[/yellow] PDF skipped (pip install reportlab)")
        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow] PDF generation failed: {e}")

    if github_issues:
        if not repo:
            console.print("[yellow]Warning:[/yellow] --repo required for GitHub Issues. Skipping.")
        else:
            _token = token or os.environ.get("GITHUB_TOKEN")
            if not _token:
                console.print("[yellow]Warning:[/yellow] No GitHub token. Set GITHUB_TOKEN env var.")
            else:
                from rlm.output import generate_github_issues
                issues = generate_github_issues(
                    report, repo=repo, token=_token,
                    dry_run=False, min_severity=min_severity,
                )
                console.print(f"  [green]✓[/green] Created [bold]{len(issues)}[/bold] GitHub Issues in [cyan]{repo}[/cyan]")

    risk_color = "red" if s.risk_score >= 70 else "yellow" if s.risk_score >= 40 else "green"
    console.print(Panel(
        f"[bold]Risk Score:[/bold] [{risk_color}]{s.risk_score}/100[/{risk_color}]  "
        f"[bold]Findings:[/bold] {s.total_findings}  "
        f"[bold]Critical:[/bold] [red]{s.by_severity.get('CRITICAL', 0)}[/red]  "
        f"[bold]High:[/bold] [orange1]{s.by_severity.get('HIGH', 0)}[/orange1]",
        title="[bold cyan]🔒 RLM Scan Complete",
        border_style="cyan",
    ))


# ── dashboard command ─────────────────────────────────────────────────────────
@app.command()
def dashboard(
    report_path: str = typer.Argument(..., help="Path to a JSON report file"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to serve the dashboard on"),
):
    """
    🌐 Launch the interactive web dashboard for a JSON report.
    """
    import json
    import http.server
    import threading
    import webbrowser

    if not os.path.exists(report_path):
        console.print(f"[red]Error:[/red] Report not found: {report_path}")
        raise typer.Exit(1)

    with open(report_path) as f:
        data = json.load(f)

    web_dir = os.path.join(os.path.dirname(__file__), "web")
    if not os.path.isdir(web_dir):
        console.print("[red]Error:[/red] Web dashboard directory not found.")
        raise typer.Exit(1)

    data_path = os.path.join(web_dir, "report_data.json")
    with open(data_path, "w") as f:
        json.dump(data, f, indent=2)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=web_dir, **kwargs)
        def log_message(self, format, *args):
            pass

    url_link = f"http://localhost:{port}"
    console.print(f"\n[bold cyan]🌐 Dashboard running at:[/bold cyan] {url_link}")
    console.print("  Press [bold]Ctrl+C[/bold] to stop\n")
    threading.Timer(1.0, lambda: webbrowser.open(url_link)).start()

    with http.server.HTTPServer(("", port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[dim]Dashboard stopped.[/dim]")


# ── Utility ───────────────────────────────────────────────────────────────────
def _safe_filename(s: str) -> str:
    import re
    s = s.replace("https://", "").replace("http://", "")
    s = s.split("/")[0]  # domain only
    s = re.sub(r"[^\w\-_]", "_", s)
    return s[:40]


if __name__ == "__main__":
    app()
