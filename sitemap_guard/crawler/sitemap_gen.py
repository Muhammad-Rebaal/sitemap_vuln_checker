"""
XML/JSON Sitemap generator (sitemaps.org compliant).
Uses orjson for fast JSON export.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import orjson

from sitemap_guard.models import CrawledURL


def generate_sitemap_xml(
    urls: Sequence[CrawledURL], output_path: Path | str, pretty_print: bool = True,
) -> Path:
    """Generate standards-compliant sitemap.xml (with index for >50K URLs)."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if len(urls) <= 50_000:
        _write_single_sitemap(urls, output_path, pretty_print)
    else:
        _write_sitemap_index(urls, output_path, 50_000, pretty_print)
    return output_path


def _write_single_sitemap(urls: Sequence[CrawledURL], path: Path, pretty: bool) -> None:
    ns = "http://www.sitemaps.org/schemas/sitemap/0.9"
    ET.register_namespace("", ns)
    urlset = ET.Element("urlset", xmlns=ns)

    for crawled in urls:
        if crawled.status_code and 200 <= crawled.status_code < 400:
            url_elem = ET.SubElement(urlset, "url")
            ET.SubElement(url_elem, "loc").text = crawled.url
            ET.SubElement(url_elem, "lastmod").text = crawled.timestamp[:10]
            ET.SubElement(url_elem, "priority").text = str(max(0.1, round(1.0 - crawled.depth * 0.2, 1)))

    tree = ET.ElementTree(urlset)
    if pretty:
        ET.indent(tree, space="  ")
    tree.write(str(path), encoding="utf-8", xml_declaration=True)


def _write_sitemap_index(
    urls: Sequence[CrawledURL], base_path: Path, chunk: int, pretty: bool,
) -> None:
    ns = "http://www.sitemaps.org/schemas/sitemap/0.9"
    ET.register_namespace("", ns)
    sitemapindex = ET.Element("sitemapindex", xmlns=ns)

    for i in range(0, len(urls), chunk):
        num = i // chunk + 1
        chunk_path = base_path.parent / f"sitemap_{num}.xml"
        _write_single_sitemap(urls[i:i + chunk], chunk_path, pretty)

        sm = ET.SubElement(sitemapindex, "sitemap")
        ET.SubElement(sm, "loc").text = f"sitemap_{num}.xml"
        ET.SubElement(sm, "lastmod").text = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    tree = ET.ElementTree(sitemapindex)
    if pretty:
        ET.indent(tree, space="  ")
    tree.write(str(base_path), encoding="utf-8", xml_declaration=True)


def generate_sitemap_json(urls: Sequence[CrawledURL], output_path: Path | str) -> Path:
    """Generate JSON sitemap using orjson (10x faster)."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_urls": len(urls),
        "urls": [url.to_dict() for url in urls],
    }
    with open(output_path, "wb") as f:
        f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))
    return output_path
