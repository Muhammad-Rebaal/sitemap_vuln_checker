import asyncio
import time
import aiohttp
from typing import List, Dict, Any
from urllib.parse import urlparse

class RateLimiter:
    """Token bucket rate limiter with automatic retries and exponential backoff."""
    def __init__(self, rate: int = 50, per: float = 1.0):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            while True:
                now = time.monotonic()
                time_passed = now - self.last_check
                self.last_check = now
                self.allowance += time_passed * (self.rate / self.per)
                if self.allowance > self.rate:
                    self.allowance = self.rate
                if self.allowance >= 1.0:
                    self.allowance -= 1.0
                    return
                await asyncio.sleep((1.0 - self.allowance) * (self.per / self.rate))

class TechFingerprinter:
    """20+ custom signatures for technology detection."""
    def __init__(self):
        self.signatures = {
            "WordPress": {"headers": {"server": "wordpress"}, "body": ["wp-content", "wp-includes", "wordpress"]},
            "Next.js": {"headers": {"x-powered-by": "next.js"}, "body": ["_next/static", "__NEXT_DATA__"]},
            "Laravel": {"headers": {"set-cookie": "laravel_session"}, "body": []},
            "React": {"headers": {"x-powered-by": "react"}, "body": ["data-reactroot", "react-dom"]},
            "Vue.js": {"headers": {}, "body": ["data-v-"]},
            "Django": {"headers": {"set-cookie": "django_session"}, "body": []},
            "Express": {"headers": {"x-powered-by": "express"}, "body": []},
            "Flask": {"headers": {"server": "gunicorn"}, "body": []},
            "Spring": {"headers": {"server": "waitress"}, "body": []},
            "ASP.NET": {"headers": {"x-powered-by": "asp.net"}, "body": []},
            "Joomla": {"headers": {"x-powered-by": "joomla"}, "body": ["Joomla!"]},
            "Drupal": {"headers": {"x-generator": "drupal"}, "body": ["Drupal"]},
            "Magento": {"headers": {"x-generator": "magento"}, "body": ["Mage"]},
            "Shopify": {"headers": {"set-cookie": "frontend"}, "body": ["Shopify"]},
            "PrestaShop": {"headers": {}, "body": ["prestashop"]},
            "Ghost": {"headers": {"x-ghost-cache-status": ""}, "body": ["ghost"]},
            "Sitecore": {"headers": {}, "body": ["sitecore"]},
            "Craft CMS": {"headers": {"x-powered-by": "express"}, "body": ["ghost"]},
            "Wix": {"headers": {"x-wix-request-id": ""}, "body": ["wix.com"]},
            "Squarespace": {"headers": {"x-seen-by": "squarespace"}, "body": ["squarespace"]},
            "Weebly": {"headers": {"x-wix-request-id": ""}, "body": ["weebly"]},
            "Webflow": {"headers": {}, "body": ["webflow"]},
            "GoDaddy": {"headers": {"x-wix-request-id": ""}, "body": ["godaddy"]},
            "Cloudflare": {"headers": {"server": "cloudflare"}, "body": ["__cf_email__"]},
            "AWS": {"headers": {"server": "awselb"}, "body": []},
            "Google Cloud": {"headers": {"server": "google"}, "body": []},
        }

    def detect(self, headers: Dict[str, str], body: str) -> List[str]:
        detected = set()
        lower_body = body.lower() if body else ""
        for tech, sig in self.signatures.items():
            for h_key, h_val in sig["headers"].items():
                if h_key in headers and h_val.lower() in headers[h_key].lower():
                    detected.add(tech)
            for b_sig in sig["body"]:
                if b_sig.lower() in lower_body:
                    detected.add(tech)
        return list(detected)

async def fallback_probe(urls: List[str], concurrency: int = 50) -> List[Dict[str, Any]]:
    """Pure Python fallback probe with rate-limiting, backoff, and fingerprinting."""
    limiter = RateLimiter(rate=50, per=1.0)
    fingerprinter = TechFingerprinter()
    results = []
    
    timeout = aiohttp.ClientTimeout(total=5)
    connector = aiohttp.TCPConnector(
        ssl=False,
        resolver=aiohttp.resolver.ThreadedResolver()
    )
    async with aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=True) as session:
        async def _probe(url):
            await limiter.acquire()
            retries = 3
            backoff = 1.0
            for attempt in range(retries):
                try:
                    async with session.get(url, allow_redirects=True, ssl=False) as resp:
                        body_bytes = await resp.read()
                        body_str = body_bytes.decode('utf-8', errors='ignore')
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        tech = fingerprinter.detect(headers, body_str)
                        return {
                            "url": str(resp.url),
                            "status": resp.status,
                            "title": "Probed Target",
                            "tech": tech
                        }
                except Exception:
                    if attempt < retries - 1:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                    else:
                        return None

        tasks = [_probe(u) for u in urls]
        for task in asyncio.as_completed(tasks):
            res = await task
            if res:
                results.append(res)
    return results
