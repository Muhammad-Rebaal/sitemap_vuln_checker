"""
selectolax-based link extractor (5-30x faster than BeautifulSoup).

Uses the Lexbor C engine via selectolax for ultra-fast HTML parsing
and CSS selector-based link extraction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

from selectolax.lexbor import LexborHTMLParser


@dataclass
class ExtractedPage:
    """All extracted data from a parsed HTML page."""
    links: list[str] = field(default_factory=list)
    title: Optional[str] = None
    meta_description: Optional[str] = None
    forms: list[dict] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    external_resources: list[str] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)


def extract_links(html_content: str, base_url: str) -> ExtractedPage:
    """
    Extract all navigable links and metadata from HTML content.
    Uses selectolax Lexbor engine — 5-30x faster than BeautifulSoup.
    """
    parser = LexborHTMLParser(html_content)
    result = ExtractedPage()

    # ── Title ─────────────────────────────────────────────────────
    title_node = parser.css_first("title")
    if title_node:
        result.title = title_node.text(strip=True)

    # ── Meta description ──────────────────────────────────────────
    meta_node = parser.css_first('meta[name="description"]')
    if meta_node:
        content = meta_node.attributes.get("content", "")
        if content:
            result.meta_description = content.strip()

    # ── Anchor links ──────────────────────────────────────────────
    seen = set()
    for node in parser.css("a[href]"):
        href = node.attributes.get("href", "").strip()
        if not href or href.startswith("#"):
            continue
        absolute = urljoin(base_url, href)
        if absolute not in seen:
            seen.add(absolute)
            result.links.append(absolute)

    # ── Forms ─────────────────────────────────────────────────────
    for form_node in parser.css("form"):
        action = form_node.attributes.get("action", "")
        method = form_node.attributes.get("method", "GET").upper()
        form_data = {
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": [],
        }
        for inp in form_node.css("input, textarea, select"):
            form_data["inputs"].append({
                "name": inp.attributes.get("name", ""),
                "type": inp.attributes.get("type", "text"),
            })
        result.forms.append(form_data)

    # ── Scripts ───────────────────────────────────────────────────
    for script_node in parser.css("script"):
        src = script_node.attributes.get("src", "")
        if src:
            result.scripts.append(urljoin(base_url, src))
        else:
            text = script_node.text(strip=True)
            if text:
                result.inline_scripts.append(text[:2000])

    # ── Iframes ───────────────────────────────────────────────────
    for iframe_node in parser.css("iframe"):
        src = iframe_node.attributes.get("src", "")
        if src:
            result.iframes.append(urljoin(base_url, src))

    # ── External resources ────────────────────────────────────────
    for node in parser.css("link[href]"):
        href = node.attributes.get("href", "")
        if href:
            result.external_resources.append(urljoin(base_url, href))

    for node in parser.css("img[src]"):
        src = node.attributes.get("src", "")
        if src:
            result.external_resources.append(urljoin(base_url, src))

    return result
