"""
JS Secret Harvester — MOD 03
Extracts all .js file references from discovered HTML pages,
fetches each JS file, and runs 30+ regex patterns to find:
  - AWS / GCP / Azure keys
  - Generic API keys & tokens
  - Firebase URLs
  - Hardcoded credentials
  - Internal endpoints
  - JWT tokens
  - Payment gateway keys (Stripe, Twilio, SendGrid)
"""
import asyncio
import re
import ssl
import structlog
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import aiohttp

logger = structlog.get_logger()

# ── Secret Patterns ────────────────────────────────────────────────────────────
SECRET_PATTERNS: List[Dict] = [
    # AWS
    {"name": "AWS Access Key ID",      "severity": "critical",
     "regex": r"AKIA[0-9A-Z]{16}"},
    {"name": "AWS Secret Key",         "severity": "critical",
     "regex": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"},

    # GCP / Firebase
    {"name": "GCP API Key",            "severity": "high",
     "regex": r"AIza[0-9A-Za-z\-_]{35}"},
    {"name": "Firebase URL",           "severity": "high",
     "regex": r"[a-z0-9-]+\.firebaseio\.com"},
    {"name": "Firebase Config",        "severity": "high",
     "regex": r"firebaseapp\.com"},

    # Generic API / Secret Keys
    {"name": "Generic API Key",        "severity": "high",
     "regex": r"(?i)api[_\-]?key\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']"},
    {"name": "Generic Secret",         "severity": "high",
     "regex": r"(?i)(?:secret|private)[_\-]?key\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']"},
    {"name": "Generic Token",          "severity": "medium",
     "regex": r"(?i)(?:auth|access)[_\-]?token\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{20,})[\"']"},

    # JWT
    {"name": "JWT Token",              "severity": "high",
     "regex": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"},

    # Payment Gateways
    {"name": "Stripe Secret Key",      "severity": "critical",
     "regex": r"sk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Publishable Key", "severity": "medium",
     "regex": r"pk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Test Key",        "severity": "low",
     "regex": r"sk_test_[0-9a-zA-Z]{24,}"},
    {"name": "Twilio Account SID",     "severity": "high",
     "regex": r"AC[a-f0-9]{32}"},
    {"name": "Twilio Auth Token",      "severity": "critical",
     "regex": r"(?i)twilio.*[\"']([a-f0-9]{32})[\"']"},
    {"name": "SendGrid API Key",       "severity": "high",
     "regex": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"},
    {"name": "PayPal Client ID",       "severity": "medium",
     "regex": r"(?i)paypal.*client.?id\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']"},

    # Credentials
    {"name": "Hardcoded Password",     "severity": "high",
     "regex": r"(?i)password\s*[:=]\s*[\"']([^\"']{8,})[\"']"},
    {"name": "Hardcoded Username",     "severity": "medium",
     "regex": r"(?i)username\s*[:=]\s*[\"']([^\"']{3,})[\"']"},
    {"name": "Basic Auth in URL",      "severity": "critical",
     "regex": r"https?://[^:@\s]+:[^@\s]+@[^\s]+"},

    # Internal Endpoints
    {"name": "Localhost Reference",    "severity": "medium",
     "regex": r"(?:https?://)?localhost(?::\d+)?(/[^\s\"']*)?"},
    {"name": "Internal IP",            "severity": "medium",
     "regex": r"(?:https?://)?(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+"},
    {"name": "Internal API Endpoint",  "severity": "medium",
     "regex": r"/api/(?:internal|private|admin|debug)/[^\s\"']*"},
    {"name": "Dev/Staging URL",        "severity": "low",
     "regex": r"https?://(?:dev|staging|test|qa|uat)\.[^\s\"']+"},

    # Cloud Storage
    {"name": "S3 Bucket URL",          "severity": "medium",
     "regex": r"[a-z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com"},
    {"name": "Azure Blob URL",         "severity": "medium",
     "regex": r"[a-z0-9\-]+\.blob\.core\.windows\.net"},
    {"name": "GCS Bucket URL",         "severity": "medium",
     "regex": r"storage\.googleapis\.com/[a-z0-9\-_]+"},

    # SSH / Private Keys
    {"name": "RSA Private Key",        "severity": "critical",
     "regex": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"},
    {"name": "PEM Certificate",        "severity": "high",
     "regex": r"-----BEGIN CERTIFICATE-----"},

    # Other
    {"name": "Slack Webhook",          "severity": "high",
     "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"},
    {"name": "GitHub Token",           "severity": "critical",
     "regex": r"gh[pousr]_[A-Za-z0-9]{36,}"},
    {"name": "NPM Token",              "severity": "high",
     "regex": r"npm_[A-Za-z0-9]{36}"},
]

_COMPILED = [(p["name"], p["severity"], re.compile(p["regex"])) for p in SECRET_PATTERNS]


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

_JS_REF_RE = re.compile(
    r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
    re.IGNORECASE,
)

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
}


def _extract_js_urls(html: str, base_url: str) -> Set[str]:
    """Extract all JS file URLs from an HTML page."""
    js_urls = set()
    for match in _JS_REF_RE.finditer(html):
        src = match.group(1).strip()
        if src.startswith("//"):
            src = "https:" + src
        elif not src.startswith("http"):
            src = urljoin(base_url, src)
        # Only keep files from same domain
        base_host = urlparse(base_url).hostname or ""
        js_host = urlparse(src).hostname or ""
        if base_host and js_host and base_host in js_host:
            js_urls.add(src.split("?")[0])  # strip query params
    return js_urls


def _scan_content(js_url: str, content: str) -> List[Dict]:
    """Run all secret patterns against JS content."""
    findings = []
    seen_names: Set[str] = set()
    for name, severity, pattern in _COMPILED:
        if name in seen_names:
            continue
        matches = pattern.findall(content)
        if matches:
            seen_names.add(name)
            # Sanitize match for display (truncate long values)
            sample = str(matches[0])[:80] if matches else ""
            findings.append({
                "type": "js_secret",
                "severity": severity,
                "name": name,
                "url": js_url,
                "details": f"Sample: {sample}",
                "match_count": len(matches),
            })
    return findings


async def _fetch_js(url: str, session: aiohttp.ClientSession) -> str:
    """Fetch a JS file, return content as string."""
    try:
        async with session.get(url, ssl=_SSL_CTX, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                return await resp.text(errors="ignore")
    except Exception as e:
        logger.debug("js_scanner.fetch_failed", url=url, error=str(e))
    return ""


async def scan_for_secrets(
    live_targets: List[Dict],
    concurrency: int = 10,
) -> List[Dict]:
    """
    Main entry point.
    1. Extract JS URLs from all live HTML pages
    2. Fetch each JS file
    3. Scan for secrets using 30+ patterns
    Returns list of finding dicts.
    """
    all_findings: List[Dict] = []
    js_url_set: Set[str] = set()

    # Step 1: Collect JS URLs from HTML content already fetched
    for target in live_targets:
        html = target.get("_html", "")
        page_url = target.get("url", "")
        if html and page_url:
            js_url_set.update(_extract_js_urls(html, page_url))

    if not js_url_set:
        logger.info("js_scanner.no_js_found")
        return []

    logger.info("js_scanner.start", js_files=len(js_url_set))

    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(
        ssl=_SSL_CTX, limit=concurrency, ttl_dns_cache=300, enable_cleanup_closed=True
    )

    async def _process(js_url: str) -> List[Dict]:
        async with semaphore:
            async with aiohttp.ClientSession(
                connector=connector,
                connector_owner=False,
                headers=_BROWSER_HEADERS,
            ) as session:
                content = await _fetch_js(js_url, session)
                if content:
                    return _scan_content(js_url, content)
        return []

    results = await asyncio.gather(
        *[_process(u) for u in js_url_set], return_exceptions=True
    )

    try:
        await connector.close()
    except Exception:
        pass

    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)

    logger.info("js_scanner.complete", secrets_found=len(all_findings))
    return all_findings
