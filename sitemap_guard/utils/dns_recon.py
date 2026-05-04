"""
DNS & WHOIS reconnaissance module.

Resolves A, MX, NS, TXT, CNAME, SOA records and extracts
SPF, DMARC, DKIM hints, email provider info, and CDN detection.
Falls back gracefully if dnspython is not installed.
"""
import asyncio
import socket
import structlog
from typing import Dict, Any, List
from urllib.parse import urlparse

logger = structlog.get_logger()


def _get_base_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc


def _resolve_dns_sync(domain: str) -> Dict[str, Any]:
    """Synchronous DNS resolution using dnspython (or socket fallback)."""
    result: Dict[str, Any] = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname": None,
        "spf": None,
        "dmarc": None,
        "email_provider": None,
        "cdn": None,
        "ip_geolocation": None,
    }

    try:
        import dns.resolver
        import dns.exception

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8

        # A records
        try:
            for rdata in resolver.resolve(domain, "A"):
                result["a_records"].append(str(rdata))
        except Exception:
            pass

        # AAAA records
        try:
            for rdata in resolver.resolve(domain, "AAAA"):
                result["aaaa_records"].append(str(rdata))
        except Exception:
            pass

        # MX records
        try:
            mx_list = []
            for rdata in resolver.resolve(domain, "MX"):
                mx_list.append({"preference": rdata.preference, "exchange": str(rdata.exchange)})
            result["mx_records"] = sorted(mx_list, key=lambda x: x["preference"])
            # Detect email providers
            email_providers = {
                "google": "Google Workspace",
                "googlemail": "Google Workspace",
                "outlook": "Microsoft 365",
                "hotmail": "Microsoft 365",
                "pphosted": "Proofpoint",
                "mimecast": "Mimecast",
                "mailgun": "Mailgun",
                "sendgrid": "SendGrid",
            }
            for mx in mx_list:
                exchange_lower = mx["exchange"].lower()
                for key, provider in email_providers.items():
                    if key in exchange_lower:
                        result["email_provider"] = provider
                        break
        except Exception:
            pass

        # NS records
        try:
            for rdata in resolver.resolve(domain, "NS"):
                result["ns_records"].append(str(rdata))
        except Exception:
            pass

        # TXT records (SPF, DMARC, general)
        try:
            for rdata in resolver.resolve(domain, "TXT"):
                txt = " ".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                result["txt_records"].append(txt)
                if txt.startswith("v=spf1"):
                    result["spf"] = txt
        except Exception:
            pass

        # DMARC
        try:
            for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
                txt = " ".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                if "v=DMARC1" in txt:
                    result["dmarc"] = txt
        except Exception:
            pass

        # CNAME
        try:
            answer = resolver.resolve(domain, "CNAME")
            result["cname"] = str(answer[0].target)
        except Exception:
            pass

        # CDN Detection from NS / A records
        cdn_signatures = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "fastly": "Fastly",
            "cdn77": "CDN77",
            "stackpath": "StackPath",
            "keycdn": "KeyCDN",
            "bunnycdn": "BunnyCDN",
            "aws": "Amazon CloudFront",
            "azureedge": "Azure CDN",
        }
        ns_str = " ".join(result["ns_records"]).lower()
        cname_str = (result["cname"] or "").lower()
        for sig, cdn_name in cdn_signatures.items():
            if sig in ns_str or sig in cname_str:
                result["cdn"] = cdn_name
                break

    except ImportError:
        # dnspython not available — use basic socket
        logger.warning("dns_recon.dnspython_missing", msg="dnspython not installed, falling back to socket")
        try:
            infos = socket.getaddrinfo(domain, None)
            result["a_records"] = list({i[4][0] for i in infos if i[0].name == "AF_INET"})
            result["aaaa_records"] = list({i[4][0] for i in infos if i[0].name == "AF_INET6"})
        except Exception as e:
            logger.debug("dns_recon.socket_failed", domain=domain, error=str(e))

    except Exception as e:
        logger.warning("dns_recon.failed", domain=domain, error=str(e))

    return result


def _probe_subdomains_sync(base_domain: str) -> List[Dict[str, Any]]:
    """
    Check common subdomains via DNS A-record lookup.
    Returns list of live subdomains.
    """
    common_subs = [
        "www", "mail", "smtp", "webmail", "admin", "api", "dev", "staging",
        "test", "portal", "vpn", "ftp", "ns1", "ns2", "cdn", "static",
        "assets", "media", "img", "images", "docs", "blog", "shop",
        "store", "app", "mobile", "m", "secure", "auth", "login",
    ]
    found = []
    for sub in common_subs:
        fqdn = f"{sub}.{base_domain}"
        try:
            addrs = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            ips = list({a[4][0] for a in addrs})
            if ips:
                found.append({"subdomain": fqdn, "ips": ips})
        except Exception:
            pass
    return found


async def run_dns_recon(target_url: str) -> Dict[str, Any]:
    """
    Async entry point. Runs DNS resolution + subdomain check in thread pool.
    """
    domain = _get_base_domain(target_url)
    # Strip www. for base domain lookups
    base = domain.lstrip("www.") if domain.startswith("www.") else domain

    logger.info("dns_recon.start", domain=domain, base=base)

    dns_info, subdomains = await asyncio.gather(
        asyncio.to_thread(_resolve_dns_sync, domain),
        asyncio.to_thread(_probe_subdomains_sync, base),
    )

    dns_info["live_subdomains"] = subdomains
    logger.info(
        "dns_recon.complete",
        domain=domain,
        a_count=len(dns_info["a_records"]),
        mx_count=len(dns_info["mx_records"]),
        subdomain_count=len(subdomains),
    )
    return dns_info
