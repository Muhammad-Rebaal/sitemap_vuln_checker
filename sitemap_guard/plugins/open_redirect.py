"""
Open Redirect Plugin
Checks if redirects (301/302) discovered during the scan 
point to a domain outside the target's base domain.
"""
from typing import List, Dict, Any
from urllib.parse import urlparse

from .base import GuardPlugin

class OpenRedirectPlugin(GuardPlugin):
    name = "OpenRedirect"
    severity = "medium"

    async def run(self, target_url: str, live_targets: List[Dict], dns_info: Dict[str, Any]) -> List[Dict]:
        findings = []
        target_domain = urlparse(target_url).hostname or ""
        
        # A simple check: if the target redirected, look at the Location header
        for t in live_targets:
            if t.get("status") in (301, 302, 307, 308):
                headers = t.get("headers", {})
                location = headers.get("location", "")
                
                if not location:
                    continue
                    
                # If location is relative, it's safe
                if location.startswith("/") and not location.startswith("//"):
                    continue
                    
                loc_parsed = urlparse(location)
                loc_domain = loc_parsed.hostname or ""
                
                # If location has a domain and it doesn't match target domain
                if loc_domain and target_domain and target_domain not in loc_domain:
                    # Ignore common SSO or expected redirects if we had a whitelist,
                    # but for now, report it
                    findings.append({
                        "type": "open_redirect",
                        "severity": self.severity,
                        "name": "Possible Open Redirect",
                        "url": t.get("url", ""),
                        "details": f"Redirects out of scope to: {location}"
                    })
                    
        return findings
