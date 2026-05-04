"""
Advanced CORS Plugin
Checks a sample of live targets for CORS misconfigurations
by sending requests with 'Origin: null' and 'Origin: https://evil.com'.
"""
import aiohttp
import asyncio
import ssl
from typing import List, Dict, Any

from .base import GuardPlugin

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

class CorsAdvancedPlugin(GuardPlugin):
    name = "CorsAdvanced"
    severity = "high"

    async def run(self, target_url: str, live_targets: List[Dict], dns_info: Dict[str, Any]) -> List[Dict]:
        findings = []
        
        # Test max 10 targets to avoid too many requests
        test_targets = live_targets[:10]
        if not test_targets:
            return []

        origins_to_test = ["null", "https://evil.com"]
        
        connector = aiohttp.TCPConnector(
            ssl=_SSL_CTX, limit=5, ttl_dns_cache=300, enable_cleanup_closed=True
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            connector_owner=False,
            timeout=aiohttp.ClientTimeout(total=8)
        ) as session:
            
            async def _test_cors(t_url: str, test_origin: str):
                try:
                    async with session.options(
                        t_url, 
                        headers={"Origin": test_origin, "Access-Control-Request-Method": "GET"}, 
                        ssl=_SSL_CTX,
                        allow_redirects=False
                    ) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                        
                        if acao == test_origin or acao == "*":
                            sev = "high" if acac.lower() == "true" else "medium"
                            return {
                                "type": "cors_misconfig",
                                "severity": sev,
                                "name": f"Advanced CORS Misconfiguration ({test_origin})",
                                "url": t_url,
                                "details": f"Reflected origin '{test_origin}', Credentials allowed: {acac}"
                            }
                except Exception:
                    pass
                return None

            tasks = []
            for t in test_targets:
                u = t.get("url")
                if u:
                    for o in origins_to_test:
                        tasks.append(_test_cors(u, o))
                        
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    findings.append(r)
                    
        try:
            await connector.close()
        except Exception:
            pass
            
        return findings
