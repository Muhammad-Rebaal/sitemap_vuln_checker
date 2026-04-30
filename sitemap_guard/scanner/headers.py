import aiohttp
from typing import Dict, List, Any
import structlog
from urllib.parse import urlparse
import asyncio
logger = structlog.get_logger()

class HeaderScanner:
    """
    Pure Python scanner for missing security headers, CORS misconfigurations,
    Cookie flags, and server disclosures natively without binaries.
    """
    
    def __init__(self, timeout: int = 5):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.findings = []
        
        self.security_headers = {
            "strict-transport-security": "Missing HSTS Header",
            "content-security-policy": "Missing CSP Header",
            "x-content-type-options": "Missing X-Content-Type-Options",
            "x-frame-options": "Missing X-Frame-Options (Clickjacking Risk)"
        }
    
    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            # We want to grab headers, so HEAD request is often sufficient, but GET ensures full headers.
            connector = aiohttp.TCPConnector(
                ssl=False,
                resolver=aiohttp.resolver.ThreadedResolver()
            )
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector, trust_env=True) as session:
                # 1. Base Request
                async with session.get(url, allow_redirects=False, ssl=False) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    # Security Headers Assessment
                    for hdr, msg in self.security_headers.items():
                        if hdr not in headers:
                            findings.append({
                                "type": "missing_header",
                                "severity": "info" if hdr != "strict-transport-security" else "low",
                                "name": msg,
                                "url": url
                            })
                            
                    # CSP Quality Check
                    if "content-security-policy" in headers:
                        csp = headers["content-security-policy"].lower()
                        if "unsafe-inline" in csp:
                            findings.append({
                                "type": "weak_csp",
                                "severity": "low",
                                "name": "CSP allows unsafe-inline",
                                "url": url
                            })
                        if "unsafe-eval" in csp:
                            findings.append({
                                "type": "weak_csp",
                                "severity": "low",
                                "name": "CSP allows unsafe-eval",
                                "url": url
                            })
                        if "*" in csp.split():
                            findings.append({
                                "type": "weak_csp",
                                "severity": "low",
                                "name": "CSP uses wildcard source",
                                "url": url
                            })
                            
                    # Disclosures
                    if "x-powered-by" in headers:
                        findings.append({
                            "type": "info_disclosure",
                            "severity": "info",
                            "name": f"X-Powered-By Header Disclosure ({headers['x-powered-by']})",
                            "url": url
                        })
                    if "server" in headers:
                        findings.append({
                            "type": "info_disclosure",
                            "severity": "info",
                            "name": f"Server Header Disclosure ({headers['server']})",
                            "url": url
                        })
                        
                    # Cookie Flags
                    if "set-cookie" in headers:
                        # aiohttp handles multiple set-cookie headers but the simple dict might just get one.
                        # Using response.raw_headers is better, but let's check basic
                        for cookie in response.cookies.values():
                            if not cookie.get("secure") and url.startswith("https"):
                                findings.append({
                                    "type": "cookie_flag",
                                    "severity": "low",
                                    "name": f"Missing Secure flag on cookie '{cookie.key}'",
                                    "url": url
                                })
                            if not cookie.get("httponly"):
                                findings.append({
                                    "type": "cookie_flag",
                                    "severity": "low",
                                    "name": f"Missing HttpOnly flag on cookie '{cookie.key}'",
                                    "url": url
                                })
                            if str(cookie.get("samesite")).lower() == "none" and not cookie.get("secure"):
                                findings.append({
                                    "type": "cookie_flag",
                                    "severity": "medium",
                                    "name": f"SameSite=None without Secure flag on cookie '{cookie.key}'",
                                    "url": url
                                })

                # 2. CORS Wildcard check
                cors_headers = {"Origin": "https://evil.com"}
                async with session.get(url, headers=cors_headers, allow_redirects=False, ssl=False) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    acao = headers.get("access-control-allow-origin", "")
                    acac = headers.get("access-control-allow-credentials", "")
                    
                    if acao == "*" or acao == "https://evil.com":
                        severity = "high" if acac.lower() == "true" else "medium"
                        findings.append({
                            "type": "cors_misconfig",
                            "severity": severity,
                            "name": f"Permissive CORS Origin ({acao})",
                            "url": url,
                            "details": f"Credentials allowed: {acac}"
                        })

        except Exception as e:
            logger.debug("header_scanner.error", url=url, error=str(e))
            findings.append({
                "type": "connection_error",
                "severity": "info",
                "name": "Connection error",
                "url": url,
                "details": str(e)
            })
            
        return findings

    async def scan_urls(self, urls: List[str], concurrency: int = 20) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(concurrency)
        all_findings = []
        
        async def _scan(url):
            async with semaphore:
                return await self.scan_url(url)
                
        tasks = [_scan(u) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if isinstance(res, list):
                all_findings.extend(res)
                
        return all_findings
