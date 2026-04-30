"""
Rich HTML dashboard report using Jinja2.
Self-contained single-file HTML with all CSS/JS inlined.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sitemap_guard.models import SiteReport


TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def generate_html_report(report: SiteReport, output_path: Path | str) -> Path:
    """Generate a self-contained HTML dashboard report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html")

    # Sort results by risk score descending
    sorted_results = sorted(report.scan_results, key=lambda r: r.risk_score, reverse=True)

    html = template.render(
        report=report,
        sorted_results=sorted_results,
        severity_counts=report.severity_counts,
        total_findings=report.total_findings,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
