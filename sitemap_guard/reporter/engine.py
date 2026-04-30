"""
Report engine — orchestrates report generation across all formats.
Uses Numba for statistical aggregation.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import structlog

from sitemap_guard.config import Settings
from sitemap_guard.models import SiteReport
from sitemap_guard.reporter.csv_report import generate_csv_report
from sitemap_guard.reporter.html_report import generate_html_report
from sitemap_guard.reporter.json_report import generate_json_report
from sitemap_guard.reporter.terminal_report import print_terminal_report
from sitemap_guard.utils.scoring import compute_response_time_stats, compute_site_risk

logger = structlog.get_logger()


class ReporterEngine:
    """Orchestrates report generation across formats."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def generate(self, report: SiteReport) -> list[Path]:
        """Generate reports in all requested formats. Returns list of output paths."""
        generated: list[Path] = []
        fmt = self.settings.report_format
        output_dir = self.settings.output_dir
        domain_safe = report.domain.replace(".", "_").replace(":", "_")

        # ── Numba-accelerated aggregation ─────────────────────────
        report.compute_overall_risk()

        # Compute response time stats via Numba
        times = [c.response_time_ms for c in report.crawled_urls if c.response_time_ms > 0]
        if times:
            time_array = np.array(times, dtype=np.float64)
            stats = compute_response_time_stats(time_array)
            report.settings_used["response_time_stats"] = {
                "min_ms": round(float(stats[0]), 2),
                "max_ms": round(float(stats[1]), 2),
                "mean_ms": round(float(stats[2]), 2),
                "median_ms": round(float(stats[3]), 2),
                "p95_ms": round(float(stats[4]), 2),
                "p99_ms": round(float(stats[5]), 2),
            }

        # ── Always print terminal report ──────────────────────────
        print_terminal_report(report)

        # ── Generate file reports ─────────────────────────────────
        if fmt in ("html", "all"):
            path = generate_html_report(report, output_dir / f"{domain_safe}_report.html")
            generated.append(path)
            logger.info("report.html_generated", path=str(path))

        if fmt in ("json", "all"):
            path = generate_json_report(report, output_dir / f"{domain_safe}_report.json")
            generated.append(path)
            logger.info("report.json_generated", path=str(path))

        if fmt in ("csv", "all"):
            path = generate_csv_report(report, output_dir / f"{domain_safe}_report.csv")
            generated.append(path)
            logger.info("report.csv_generated", path=str(path))

        return generated
