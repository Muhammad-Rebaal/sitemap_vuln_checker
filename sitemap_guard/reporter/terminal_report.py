"""
Terminal report — rich console output with colors and tables.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sitemap_guard.models import Severity, SiteReport


def print_terminal_report(report: SiteReport, console: Console | None = None) -> None:
    """Print a beautiful terminal summary of the scan results."""
    if console is None:
        console = Console()

    # ── Header ────────────────────────────────────────────────────
    console.print()
    console.print(Panel.fit(
        f"[bold white]SiteMap Guard v2.0 — Scan Report[/]\n"
        f"[dim]{report.target_url}[/]",
        border_style="cyan",
    ))

    # ── Summary Stats ─────────────────────────────────────────────
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()

    risk_color = "green"
    if report.overall_risk_score >= 75:
        risk_color = "red"
    elif report.overall_risk_score >= 50:
        risk_color = "dark_orange"
    elif report.overall_risk_score >= 25:
        risk_color = "yellow"

    summary.add_row("Domain", report.domain)
    summary.add_row("URLs Discovered", str(report.total_urls_discovered))
    summary.add_row("URLs Scanned", str(report.total_urls_scanned))
    summary.add_row("Total Findings", str(report.total_findings))
    summary.add_row("Overall Risk", f"[bold {risk_color}]{report.overall_risk_score:.1f}/100[/]")
    summary.add_row("Crawl Time", f"{report.crawl_duration_seconds:.1f}s")
    summary.add_row("Scan Time", f"{report.scan_duration_seconds:.1f}s")
    summary.add_row("Total Time", f"{report.total_duration_seconds:.1f}s")

    console.print(Panel(summary, title="[bold]Summary", border_style="blue"))

    # ── Severity Breakdown ────────────────────────────────────────
    counts = report.severity_counts
    sev_table = Table(show_header=True, header_style="bold")
    sev_table.add_column("Severity", justify="center")
    sev_table.add_column("Count", justify="center")
    sev_table.add_column("Bar", justify="left", min_width=30)

    max_count = max(counts.values()) if any(counts.values()) else 1
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev = Severity(sev_name)
        count = counts[sev_name]
        bar_len = int((count / max_count) * 25) if max_count > 0 else 0
        bar = "█" * bar_len
        sev_table.add_row(
            Text(sev_name, style=f"bold {sev.color}"),
            str(count),
            Text(bar, style=sev.color),
        )

    console.print(Panel(sev_table, title="[bold]Severity Distribution", border_style="magenta"))

    # ── Top Risky URLs ────────────────────────────────────────────
    if report.scan_results:
        sorted_results = sorted(report.scan_results, key=lambda r: r.risk_score, reverse=True)
        top_n = min(15, len(sorted_results))

        url_table = Table(show_header=True, header_style="bold", show_lines=True)
        url_table.add_column("Risk", justify="center", width=6)
        url_table.add_column("URL", max_width=60, no_wrap=True)
        url_table.add_column("C", justify="center", width=3, style="red")
        url_table.add_column("H", justify="center", width=3, style="dark_orange")
        url_table.add_column("M", justify="center", width=3, style="yellow")
        url_table.add_column("L", justify="center", width=3, style="cyan")
        url_table.add_column("I", justify="center", width=3, style="dim")

        for r in sorted_results[:top_n]:
            rc = "green"
            if r.risk_score >= 75:
                rc = "red"
            elif r.risk_score >= 50:
                rc = "dark_orange"
            elif r.risk_score >= 25:
                rc = "yellow"

            url_display = r.url
            if len(url_display) > 58:
                url_display = url_display[:55] + "..."

            url_table.add_row(
                Text(f"{r.risk_score:.0f}", style=f"bold {rc}"),
                url_display,
                str(r.critical_count) if r.critical_count else "-",
                str(r.high_count) if r.high_count else "-",
                str(r.medium_count) if r.medium_count else "-",
                str(r.low_count) if r.low_count else "-",
                str(r.info_count) if r.info_count else "-",
            )

        console.print(Panel(url_table, title=f"[bold]Top {top_n} Risky URLs", border_style="red"))

    console.print()
