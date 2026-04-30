"""
CSV report export for spreadsheet analysis.
"""

from __future__ import annotations

import csv
from pathlib import Path

from sitemap_guard.models import SiteReport


def generate_csv_report(report: SiteReport, output_path: Path | str) -> Path:
    """Generate CSV report with one row per finding."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "URL", "Risk Score", "Analyzer", "Severity",
            "Title", "Description", "Evidence", "Remediation", "CWE",
        ])

        for result in report.scan_results:
            for finding in result.findings:
                writer.writerow([
                    result.url,
                    result.risk_score,
                    finding.analyzer_name,
                    finding.severity.value,
                    finding.title,
                    finding.description,
                    finding.evidence,
                    finding.remediation,
                    finding.cwe_id or "",
                ])

    return output_path
