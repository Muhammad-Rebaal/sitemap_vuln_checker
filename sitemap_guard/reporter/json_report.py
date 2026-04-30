"""
JSON report export using orjson (10x faster than stdlib json).
"""

from __future__ import annotations

from pathlib import Path

import orjson

from sitemap_guard.models import SiteReport


def generate_json_report(report: SiteReport, output_path: Path | str) -> Path:
    """Generate JSON report using orjson for maximum speed."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "wb") as f:
        f.write(orjson.dumps(report.to_dict(), option=orjson.OPT_INDENT_2))

    return output_path
