"""
HTTP fingerprinting utilities for technology detection.

Signature databases for servers, CMS, frameworks, CDN/WAF, and analytics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


SERVER_SIGNATURES: dict[str, str] = {
    "apache": "Apache HTTP Server", "nginx": "Nginx", "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed", "cloudflare": "Cloudflare", "gunicorn": "Gunicorn (Python)",
    "uvicorn": "Uvicorn (Python)", "express": "Express.js (Node)",
    "openresty": "OpenResty (Nginx)", "caddy": "Caddy Server", "envoy": "Envoy Proxy",
}

CMS_SIGNATURES: dict[str, list[str]] = {
    "WordPress": ["wp-content/", "wp-includes/", 'content="WordPress', "wp-json/"],
    "Drupal": ["Drupal.settings", "drupal.js", 'content="Drupal'],
    "Joomla": ["/media/system/js/", "/administrator/", 'content="Joomla'],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Wix": ["wix.com", "static.wixstatic.com"],
    "Squarespace": ["squarespace.com", "static1.squarespace.com"],
}

FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "React": ["react", "_next/", "__next", "reactroot"],
    "Next.js": ["_next/static", "__NEXT_DATA__"],
    "Vue.js": ["vue.js", "__vue__", "vue-router"],
    "Nuxt.js": ["_nuxt/", "__nuxt"],
    "Angular": ["ng-version", "angular", "ng-app"],
    "Django": ["csrfmiddlewaretoken", "djdt"],
    "Flask": ["Werkzeug"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Ruby on Rails": ["_rails", "csrf-token", "authenticity_token"],
    "ASP.NET": ["__VIEWSTATE", "__EVENTVALIDATION", "asp.net"],
    "Spring Boot": ["X-Application-Context", "Whitelabel Error Page"],
}

ANALYTICS_SIGNATURES: dict[str, list[str]] = {
    "Google Analytics": ["google-analytics.com", "googletagmanager.com", "gtag("],
    "Matomo": ["matomo.js", "piwik.js"],
    "Hotjar": ["hotjar.com"],
    "Plausible": ["plausible.io"],
}

SECURITY_TOOL_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["__cf_bm", "cf-ray", "cloudflare"],
    "Akamai": ["akamai", "akamaized"],
    "AWS WAF": ["awswaf", "aws-waf-token"],
    "Sucuri": ["sucuri", "cloudproxy"],
    "reCAPTCHA": ["recaptcha", "grecaptcha"],
    "hCaptcha": ["hcaptcha"],
}


@dataclass
class TechFingerprint:
    """Detected technology fingerprint."""
    category: str
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: str = ""


def detect_server(headers: dict[str, str]) -> Optional[TechFingerprint]:
    """Detect web server from response headers."""
    server = headers.get("server", "").lower()
    if not server:
        return None
    for sig, name in SERVER_SIGNATURES.items():
        if sig in server:
            version = None
            parts = server.split("/")
            if len(parts) > 1:
                version = parts[1].split(" ")[0]
            return TechFingerprint(
                category="server", name=name, version=version,
                confidence=0.9, evidence=f"Server: {headers.get('server', '')}",
            )
    return TechFingerprint(category="server", name=server, confidence=0.7,
                           evidence=f"Server: {headers.get('server', '')}")


def detect_from_content(
    content: str, signatures: dict[str, list[str]], category: str,
) -> list[TechFingerprint]:
    """Detect technologies from page content using signature matching."""
    results = []
    content_lower = content.lower()
    for tech_name, patterns in signatures.items():
        matches = sum(1 for p in patterns if p.lower() in content_lower)
        if matches > 0:
            confidence = min(1.0, matches / len(patterns))
            matched = [p for p in patterns if p.lower() in content_lower]
            results.append(TechFingerprint(
                category=category, name=tech_name, confidence=confidence,
                evidence=f"Matched: {', '.join(matched[:3])}",
            ))
    return results


def detect_from_headers(headers: dict[str, str]) -> list[TechFingerprint]:
    """Detect technologies from response headers."""
    results = []
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        results.append(TechFingerprint(
            category="framework", name=powered_by, confidence=0.9,
            evidence=f"X-Powered-By: {powered_by}",
        ))
    header_str = str(headers).lower()
    for tech_name, patterns in SECURITY_TOOL_SIGNATURES.items():
        for pattern in patterns:
            if pattern.lower() in header_str:
                results.append(TechFingerprint(
                    category="security", name=tech_name, confidence=0.85,
                    evidence=f"Header match: {pattern}",
                ))
                break
    return results
