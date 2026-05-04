"""
Passive URL Aggregator — MOD 01
Pulls historical URLs from free, open-source APIs:
  - Wayback Machine CDX API
  - CommonCrawl Index
  - AlienVault OTX passive DNS

No API keys required. All results are merged and deduplicated.
"""
import asyncio
import re
import structlog
from typing import List, Set
from urllib.parse import urlparse

import httpx

logger = structlog.get_logger()

# Timeout for each passive source (seconds)
_TIMEOUT = 12.0

# File extensions to discard from passive results
_SKIP_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".svg",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov",
}


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    # Strip www. prefix for broader queries
    return re.sub(r"^www\.", "", host)


def _filter_url(url: str, base_domain: str) -> bool:
    """Return True if URL should be kept."""
    if not url or not url.startswith("http"):
        return False
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if base_domain not in host:
        return False
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in _SKIP_EXTS):
        return False
    return True


async def _fetch_wayback(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Query Wayback Machine CDX API for historical URLs."""
    urls: Set[str] = set()
    endpoint = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original"
        f"&collapse=urlkey&limit=3000&filter=statuscode:200"
    )
    try:
        resp = await client.get(endpoint, timeout=_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            # First row is header ["original"]
            for row in data[1:]:
                if row and isinstance(row, list):
                    urls.add(row[0])
            logger.info("passive_recon.wayback", count=len(urls), domain=domain)
    except Exception as e:
        logger.debug("passive_recon.wayback_failed", domain=domain, error=str(e))
    return urls


async def _fetch_commoncrawl(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Query CommonCrawl index for URLs."""
    urls: Set[str] = set()
    # Use the latest index — this URL is stable
    endpoint = (
        f"https://index.commoncrawl.org/CC-MAIN-2024-10-index"
        f"?url=*.{domain}&output=json&limit=2000"
    )
    try:
        resp = await client.get(endpoint, timeout=_TIMEOUT)
        if resp.status_code == 200:
            import orjson
            for line in resp.text.strip().splitlines():
                if line.strip():
                    try:
                        obj = orjson.loads(line)
                        u = obj.get("url", "")
                        if u:
                            urls.add(u)
                    except Exception:
                        pass
            logger.info("passive_recon.commoncrawl", count=len(urls), domain=domain)
    except Exception as e:
        logger.debug("passive_recon.commoncrawl_failed", domain=domain, error=str(e))
    return urls


async def _fetch_otx(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Query AlienVault OTX for passive DNS URL list (no auth required for basic data)."""
    urls: Set[str] = set()
    endpoint = (
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        f"?limit=500&page=1"
    )
    try:
        resp = await client.get(
            endpoint,
            timeout=_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 SiteMapGuard/4.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("url_list", []):
                u = entry.get("url", "")
                if u:
                    urls.add(u)
            logger.info("passive_recon.otx", count=len(urls), domain=domain)
    except Exception as e:
        logger.debug("passive_recon.otx_failed", domain=domain, error=str(e))
    return urls


async def run_passive_recon(target_url: str, timeout: float = 15.0) -> List[str]:
    """
    Aggregate historical URLs from Wayback, CommonCrawl, and OTX.
    Returns deduplicated list filtered to the target domain.
    Runs all 3 sources concurrently; each has its own per-source timeout.
    """
    domain = _extract_domain(target_url)
    if not domain:
        logger.warning("passive_recon.invalid_target", url=target_url)
        return []

    logger.info("passive_recon.start", domain=domain)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=httpx.Timeout(timeout),
    ) as client:
        wayback_task = asyncio.create_task(_fetch_wayback(domain, client))
        cc_task = asyncio.create_task(_fetch_commoncrawl(domain, client))
        otx_task = asyncio.create_task(_fetch_otx(domain, client))

        results = await asyncio.gather(
            wayback_task, cc_task, otx_task, return_exceptions=True
        )

    merged: Set[str] = set()
    for r in results:
        if isinstance(r, set):
            merged.update(r)

    # Filter to target domain only
    filtered = [u for u in merged if _filter_url(u, domain)]

    logger.info(
        "passive_recon.complete",
        domain=domain,
        raw=len(merged),
        filtered=len(filtered),
    )
    return filtered
