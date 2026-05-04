"""
Resilient HTTP probing with SSL bypass (including legacy server support),
requests-based fallback, and tech fingerprinting.
"""
import asyncio
import random
import ssl
import string
import time
import aiohttp
import requests
import structlog
import xxhash
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from requests.adapters import HTTPAdapter

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# SSL context — disables cert verification + enables legacy server connect
# for servers that do premature EOF during TLS handshake (UNEXPECTED_EOF)
# ---------------------------------------------------------------------------
def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    # Python 3.12+ — allows servers that close the connection early
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT  # type: ignore[attr-defined]
    return ctx


_SSL_CTX = _make_ssl_ctx()


# ---------------------------------------------------------------------------
# Custom requests adapter — same legacy SSL settings for broken TLS servers
# ---------------------------------------------------------------------------
class _LegacySSLAdapter(HTTPAdapter):
    """Requests adapter that uses the legacy SSL context."""

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = _make_ssl_ctx()
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = _make_ssl_ctx()
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _make_requests_session() -> requests.Session:
    session = requests.Session()
    adapter = _LegacySSLAdapter(max_retries=1)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


# ---------------------------------------------------------------------------
# Tech fingerprinter
# ---------------------------------------------------------------------------
class TechFingerprinter:
    def __init__(self):
        self.signatures = {
            "WordPress":    {"headers": {"server": "wordpress"}, "body": ["wp-content", "wp-includes", "wordpress"]},
            "Next.js":      {"headers": {"x-powered-by": "next.js"}, "body": ["_next/static", "__NEXT_DATA__"]},
            "Laravel":      {"headers": {"set-cookie": "laravel_session"}, "body": ["laravel"]},
            "React":        {"headers": {"x-powered-by": "react"}, "body": ["data-reactroot", "react-dom"]},
            "Vue.js":       {"headers": {}, "body": ["data-v-", "vue.js", "vue.min.js"]},
            "Django":       {"headers": {"set-cookie": "django_session"}, "body": ["django"]},
            "Express":      {"headers": {"x-powered-by": "express"}, "body": []},
            "Flask":        {"headers": {"server": "gunicorn"}, "body": []},
            "ASP.NET":      {"headers": {"x-powered-by": "asp.net", "x-aspnet-version": ""}, "body": ["__viewstate", "aspnetForm"]},
            "ASP.NET Core": {"headers": {"x-powered-by": "asp.net"}, "body": ["aspnetcore"]},
            "PHP":          {"headers": {"x-powered-by": "php"}, "body": []},
            "Joomla":       {"headers": {}, "body": ["joomla!", "/component/", "option=com_"]},
            "Drupal":       {"headers": {"x-generator": "drupal"}, "body": ["drupal", "sites/all/"]},
            "Magento":      {"headers": {"x-magento-cache-control": ""}, "body": ["mage", "magento"]},
            "Shopify":      {"headers": {"x-shopify-stage": ""}, "body": ["shopify"]},
            "Cloudflare":   {"headers": {"server": "cloudflare", "cf-ray": ""}, "body": ["__cf_email__", "cdn-cgi"]},
            "AWS":          {"headers": {"server": "awselb", "x-amz-request-id": ""}, "body": []},
            "Nginx":        {"headers": {"server": "nginx"}, "body": []},
            "Apache":       {"headers": {"server": "apache"}, "body": []},
            "IIS":          {"headers": {"server": "microsoft-iis"}, "body": []},
            "Bootstrap":    {"headers": {}, "body": ["bootstrap.min.css", "bootstrap.min.js"]},
            "jQuery":       {"headers": {}, "body": ["jquery.min.js", "jquery-"]},
            "Google Analytics": {"headers": {}, "body": ["google-analytics.com/analytics.js", "gtag("]},
        }

    def detect(self, headers: Dict[str, str], body: str) -> List[str]:
        detected = set()
        lower_body = body.lower() if body else ""
        lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
        for tech, sig in self.signatures.items():
            for h_key, h_val in sig["headers"].items():
                if h_key in lower_headers and (not h_val or h_val in lower_headers[h_key]):
                    detected.add(tech)
            for b_sig in sig["body"]:
                if b_sig.lower() in lower_body:
                    detected.add(tech)
        return list(detected)


_FINGERPRINTER = TechFingerprinter()


def _extract_title(body: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else ""


# ---------------------------------------------------------------------------
# Synchronous requests probe (runs in thread pool)
# ---------------------------------------------------------------------------
def _requests_probe(url: str) -> Optional[Dict[str, Any]]:
    try:
        session = _make_requests_session()
        resp = session.get(
            url,
            headers=_BROWSER_HEADERS,
            timeout=(8, 15),
            verify=False,
            allow_redirects=True,
        )
        body = resp.text
        headers = {k.lower(): v for k, v in resp.headers.items()}
        tech = _FINGERPRINTER.detect(headers, body)
        title = _extract_title(body)
        return {
            "url": resp.url if isinstance(resp.url, str) else str(resp.url),
            "status": resp.status_code,
            "title": title or "No Title",
            "tech": tech,
            "headers": dict(headers),
            "_html": body,
            "_hash": xxhash.xxh64(body.encode("utf-8")).hexdigest(),
        }
    except Exception as e:
        logger.debug("probe.requests_failed", url=url, error=str(e))
        return None


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, rate: int = 30, per: float = 1.0):
        self.rate = rate
        self.per = per
        self.allowance = float(rate)
        self.last_check = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            while True:
                now = time.monotonic()
                self.allowance += (now - self.last_check) * (self.rate / self.per)
                self.last_check = now
                if self.allowance > self.rate:
                    self.allowance = float(self.rate)
                if self.allowance >= 1.0:
                    self.allowance -= 1.0
                    return
                await asyncio.sleep((1.0 - self.allowance) * (self.per / self.rate))


# ---------------------------------------------------------------------------
# Main probe entry point
# ---------------------------------------------------------------------------
async def fallback_probe(urls: List[str], target_url: str = "", concurrency: int = 15) -> List[Dict[str, Any]]:
    """
    Probe URLs: tries aiohttp first (with proper SSL legacy bypass),
    then falls back to requests in a thread pool for broken-TLS servers.
    Implements a Soft-404 Baseline filter to ignore noisy redirects.
    """
    limiter = RateLimiter(rate=20, per=1.0)
    results = []
    timeout = aiohttp.ClientTimeout(total=15, connect=8, sock_connect=8, sock_read=12)

    connector = aiohttp.TCPConnector(
        ssl=_SSL_CTX,
        limit=concurrency,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    async def _probe_one(url: str) -> Optional[Dict[str, Any]]:
        await limiter.acquire()
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                connector_owner=False,
                headers=_BROWSER_HEADERS,
            ) as session:
                async with session.get(url, allow_redirects=True, ssl=_SSL_CTX) as resp:
                    body_bytes = await resp.read()
                    body_str = body_bytes.decode("utf-8", errors="ignore")
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    tech = _FINGERPRINTER.detect(headers, body_str)
                    title = _extract_title(body_str)
                    return {
                        "url": str(resp.url),
                        "status": resp.status,
                        "title": title or "Probed",
                        "tech": tech,
                        "headers": dict(headers),
                        "_html": body_str,
                        "_hash": xxhash.xxh64(body_bytes).hexdigest(),
                    }
        except Exception:
            pass
        return await asyncio.to_thread(_requests_probe, url)

    # Compute baseline for soft-404 detection
    baseline_hashes = set()
    base = target_url or (urls[0] if urls else "")
    if base:
        parsed = urlparse(base)
        base_host = f"{parsed.scheme}://{parsed.netloc}"
        for _ in range(2):
            rnd = "".join(random.choices(string.ascii_letters + string.digits, k=12))
            test_url = urljoin(base_host, f"/sitemap_guard_canary_{rnd}")
            res = await _probe_one(test_url)
            if res and "_hash" in res:
                baseline_hashes.add(res["_hash"])
                
        if baseline_hashes:
            logger.info("probe.baseline", hashes=list(baseline_hashes))

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(url: str):
        async with semaphore:
            res = await _probe_one(url)
            # Soft-404 filter
            if res and "_hash" in res and res["_hash"] in baseline_hashes:
                # If it's the exact same as a canary, it's a soft-404
                if url != base and url != base_host and url != base_host + "/":
                    return None
            return res

    raw = await asyncio.gather(*[_bounded(u) for u in urls], return_exceptions=True)

    try:
        await connector.close()
    except Exception:
        pass

    for res in raw:
        if isinstance(res, dict) and res:
            # We remove _html and _hash here if we want to save memory, 
            # but JS scanner needs _html. Keep it.
            results.append(res)
    return results
