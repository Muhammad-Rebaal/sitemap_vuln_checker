"""
Resilient security header scanner.
Tries aiohttp first, falls back to requests (with legacy SSL adapter) for
servers that send UNEXPECTED_EOF during TLS handshake.
"""
import asyncio
import ssl
import aiohttp
import requests
import structlog
from typing import Dict, List, Any
from requests.adapters import HTTPAdapter

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Shared SSL context + legacy adapter (same as probe.py)
# ---------------------------------------------------------------------------
def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT  # type: ignore[attr-defined]
    return ctx


_SSL_CTX = _make_ssl_ctx()


class _LegacySSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = _make_ssl_ctx()
        super().init_poolmanager(*args, **kwargs)


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
}

SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS Header", "low"),
    "content-security-policy": ("Missing CSP Header", "info"),
    "x-content-type-options": ("Missing X-Content-Type-Options", "info"),
    "x-frame-options": ("Missing X-Frame-Options (Clickjacking Risk)", "info"),
    "referrer-policy": ("Missing Referrer-Policy Header", "info"),
    "permissions-policy": ("Missing Permissions-Policy Header", "info"),
}


def _scan_headers_dict(headers: Dict[str, str], url: str, status: int) -> List[Dict[str, Any]]:
    findings = []
    for hdr, (msg, sev) in SECURITY_HEADERS.items():
        if hdr not in headers:
            findings.append({"type": "missing_header", "severity": sev, "name": msg, "url": url})

    if "content-security-policy" in headers:
        csp = headers["content-security-policy"].lower()
        if "unsafe-inline" in csp:
            findings.append({"type": "weak_csp", "severity": "low", "name": "CSP allows unsafe-inline", "url": url})
        if "unsafe-eval" in csp:
            findings.append({"type": "weak_csp", "severity": "low", "name": "CSP allows unsafe-eval", "url": url})

    if "x-powered-by" in headers:
        findings.append({"type": "info_disclosure", "severity": "info",
                         "name": f"X-Powered-By Disclosure ({headers['x-powered-by']})", "url": url})
    if "server" in headers:
        findings.append({"type": "info_disclosure", "severity": "info",
                         "name": f"Server Header Disclosure ({headers['server']})", "url": url})
    return findings


def _requests_scan_sync(url: str) -> List[Dict[str, Any]]:
    """Synchronous scan via requests + legacy SSL adapter."""
    findings = []
    try:
        session = _make_requests_session()
        resp = session.get(
            url,
            headers={**_BROWSER_HEADERS, "Origin": "https://evil.com"},
            timeout=(8, 15),
            verify=False,
            allow_redirects=False,
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
        findings += _scan_headers_dict(headers, url, resp.status_code)

        # CORS check
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao in ("*", "https://evil.com"):
            sev = "high" if acac.lower() == "true" else "medium"
            findings.append({"type": "cors_misconfig", "severity": sev,
                             "name": f"Permissive CORS Origin ({acao})", "url": url,
                             "details": f"Credentials allowed: {acac}"})

        # Cookie flags
        for cookie in resp.cookies:
            if not cookie.secure and url.startswith("https"):
                findings.append({"type": "cookie_flag", "severity": "low",
                                  "name": f"Missing Secure flag on cookie '{cookie.name}'", "url": url})

    except Exception as e:
        findings.append({"type": "connection_error", "severity": "info",
                         "name": "Connection error", "url": url, "details": str(e)})
    return findings


class HeaderScanner:
    """
    Security header scanner with aiohttp → requests fallback.
    Does NOT use ThreadedResolver (conflicts with dnspython causing DNS failures).
    """

    def __init__(self, timeout: int = 15):
        # NOTE: No ThreadedResolver — use asyncio default resolver
        self._timeout = aiohttp.ClientTimeout(total=timeout, connect=8, sock_connect=8)

    async def scan_url(self, url: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        findings = []
        try:
            async with session.get(url, allow_redirects=False, ssl=_SSL_CTX) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                findings += _scan_headers_dict(headers, url, resp.status)

                # Cookie flags
                for cookie in resp.cookies.values():
                    if not cookie.get("secure") and url.startswith("https"):
                        findings.append({"type": "cookie_flag", "severity": "low",
                                         "name": f"Missing Secure flag on cookie '{cookie.key}'", "url": url})
                    if not cookie.get("httponly"):
                        findings.append({"type": "cookie_flag", "severity": "low",
                                         "name": f"Missing HttpOnly flag on cookie '{cookie.key}'", "url": url})

            # CORS probe
            async with session.get(url, headers={"Origin": "https://evil.com"},
                                   allow_redirects=False, ssl=_SSL_CTX) as cors_resp:
                ch = {k.lower(): v for k, v in cors_resp.headers.items()}
                acao = ch.get("access-control-allow-origin", "")
                acac = ch.get("access-control-allow-credentials", "")
                if acao in ("*", "https://evil.com"):
                    sev = "high" if acac.lower() == "true" else "medium"
                    findings.append({"type": "cors_misconfig", "severity": sev,
                                     "name": f"Permissive CORS Origin ({acao})", "url": url,
                                     "details": f"Credentials: {acac}"})

        except Exception as e:
            logger.debug("header_scanner.aiohttp_failed", url=url, error=str(e))
            # Fall back to blocking requests in thread pool
            findings = await asyncio.to_thread(_requests_scan_sync, url)

        return findings

    async def scan_urls(self, urls: List[str], concurrency: int = 8) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(concurrency)
        all_findings: List[Dict[str, Any]] = []

        # No ThreadedResolver — avoids "Could not contact DNS servers" with dnspython
        connector = aiohttp.TCPConnector(
            ssl=_SSL_CTX,
            limit=concurrency,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

        async with aiohttp.ClientSession(
            timeout=self._timeout,
            connector=connector,
            headers=_BROWSER_HEADERS,
        ) as session:
            async def _scan(url: str):
                async with semaphore:
                    return await self.scan_url(url, session)

            results = await asyncio.gather(*[_scan(u) for u in urls], return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                all_findings.extend(res)
        return all_findings
