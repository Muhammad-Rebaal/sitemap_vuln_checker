"""
Enhanced sitemap reporter that generates URL | Status | Classification | Redirect
format reports with vulnerability classification (clean/virus).

Output filename: <domain>_report_<YYYYMMDD_HHMMSS>.txt
"""
import re
import asyncio
import ssl
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
import structlog

logger = structlog.get_logger()


class EnhancedSitemapReporter:
    """
    Enhanced reporter that creates comprehensive sitemap reports with:
    - URL | Status | Classification | Redirect format
    - Vulnerability classification (clean/virus)
    - Complete link discovery and redirect tracking
    - Domain-based report naming (<domain>_report_<date_time>.txt)
    """

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    COMMON_PATHS = [
        "/", "/index.html", "/index.php", "/home", "/about", "/contact",
        "/login", "/register", "/admin", "/dashboard", "/profile",
        "/search", "/help", "/support", "/faq", "/terms", "/privacy",
        "/blog", "/news", "/products", "/services", "/portfolio",
        "/api", "/api/v1", "/api/v2", "/docs", "/documentation",
        "/upload", "/uploads", "/files", "/images", "/assets",
        "/js", "/css", "/fonts", "/media", "/downloads",
        "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
        "/admin.php", "/administrator", "/panel", "/control",
        "/config.php", "/setup.php", "/install.php", "/test.php",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    ]

    SUSPICIOUS_URL_PATTERNS = [
        r"\.php\?.*=.*\.\.",      # Path traversal
        r"union\s+select",         # SQL injection
        r"<\s*script",             # XSS attempts
        r"javascript:",            # JS protocol
        r"vbscript:",              # VBScript protocol
        r"data:text/html",         # Data URI HTML
    ]

    def __init__(self, target_url: str, output_dir: str = "./reports"):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.domain = urlparse(self.target_url).netloc or self.target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        self._compiled_suspicious = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_URL_PATTERNS]

    async def generate_enhanced_report(self, scan_results: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate the enhanced sitemap report in the requested format:
        URL | Status | Classification | Redirect

        Returns: Path (string) of the generated report file.
        """
        scan_results = scan_results or {}
        logger.info("enhanced_reporter.starting", domain=self.domain)

        all_urls = await self._collect_all_urls(scan_results)
        url_data = await self._process_urls(all_urls)
        classified_data = self._classify_vulnerabilities(url_data, scan_results)
        report_path = self._generate_report_file(classified_data)

        logger.info(
            "enhanced_reporter.completed",
            report_path=str(report_path),
            total_urls=len(classified_data),
        )
        return str(report_path)

    async def _collect_all_urls(self, scan_results: Dict[str, Any]) -> List[str]:
        """Collect URLs from scan results and discovery methods."""
        urls = set()
        urls.add(self.target_url)

        for target in scan_results.get("live_targets", []) or []:
            url = target.get("url")
            if url:
                urls.add(url)

        for url_list_key in ("urls", "discovered_urls"):
            for url in scan_results.get(url_list_key, []) or []:
                if url:
                    urls.add(url)

        additional = await self._discover_additional_urls()
        urls.update(additional)
        return list(urls)

    async def _discover_additional_urls(self) -> List[str]:
        """Discover URLs via robots.txt, sitemap.xml, common paths, and link extraction."""
        urls = set()
        async with self._make_session(timeout=15) as session:
            robots = await self._parse_robots_txt(session)
            urls.update(robots)

            sitemap_urls = await self._parse_sitemaps(session)
            urls.update(sitemap_urls)

            urls.update(self._common_path_urls())

            extracted = await self._extract_links_from_pages(session, [self.target_url])
            urls.update(extracted)
        return list(urls)

    def _make_session(self, timeout: int = 10) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(
            headers=self.DEFAULT_HEADERS,
            connector=aiohttp.TCPConnector(ssl=self.ssl_context, limit=20),
            timeout=aiohttp.ClientTimeout(total=timeout),
        )

    async def _parse_robots_txt(self, session: aiohttp.ClientSession) -> List[str]:
        urls: List[str] = []
        robots_url = f"{self.target_url}/robots.txt"
        try:
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    for line in content.splitlines():
                        line = line.strip()
                        if line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            if sitemap_url:
                                urls.append(sitemap_url)
                        elif line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/" and "*" not in path:
                                urls.append(urljoin(self.target_url + "/", path.lstrip("/")))
        except Exception as e:
            logger.debug("robots_parse_failed", error=str(e))
        return urls

    async def _parse_sitemaps(self, session: aiohttp.ClientSession) -> List[str]:
        urls: List[str] = []
        candidates = [
            f"{self.target_url}/sitemap.xml",
            f"{self.target_url}/sitemap_index.xml",
            f"{self.target_url}/sitemap-index.xml",
            f"{self.target_url}/wp-sitemap.xml",
            f"{self.target_url}/sitemap1.xml",
            f"{self.target_url}/sitemaps.xml",
        ]
        loc_pattern = re.compile(r"<loc>([^<]+)</loc>", re.IGNORECASE)
        for sitemap_url in candidates:
            try:
                async with session.get(sitemap_url) as response:
                    if response.status == 200:
                        content = await response.text(errors="ignore")
                        urls.extend(loc_pattern.findall(content))
            except Exception as e:
                logger.debug("sitemap_parse_failed", url=sitemap_url, error=str(e))
        return urls

    def _common_path_urls(self) -> List[str]:
        return [urljoin(self.target_url + "/", path.lstrip("/")) for path in self.COMMON_PATHS]

    async def _extract_links_from_pages(
        self, session: aiohttp.ClientSession, page_urls: List[str]
    ) -> List[str]:
        all_links = set()
        for url in page_urls[:5]:
            try:
                async with session.get(url) as response:
                    ctype = response.headers.get("content-type", "")
                    if response.status == 200 and "text/html" in ctype.lower():
                        content = await response.text(errors="ignore")
                        all_links.update(self._extract_links_from_html(content, url))
            except Exception as e:
                logger.debug("link_extraction_failed", url=url, error=str(e))
        return list(all_links)

    _HREF_RE = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.IGNORECASE)

    def _extract_links_from_html(self, html_content: str, base_url: str) -> List[str]:
        links = []
        for raw in self._HREF_RE.findall(html_content):
            link = raw.strip()
            if not link or link.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            if link.startswith("//"):
                link = "https:" + link
            full_url = urljoin(base_url, link)
            parsed = urlparse(full_url)
            if parsed.netloc and (parsed.netloc == self.domain or parsed.netloc.endswith("." + self.domain)):
                links.append(full_url)
        return links

    async def _process_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Fetch status/redirect/title for each URL with bounded concurrency."""
        results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(20)
        async with self._make_session(timeout=12) as session:
            async def bounded(url: str):
                async with sem:
                    return await self._process_single_url(session, url)

            tasks = [bounded(url) for url in urls]
            for coro in asyncio.as_completed(tasks):
                try:
                    res = await coro
                    if isinstance(res, dict):
                        results.append(res)
                except Exception as e:
                    logger.debug("url_processing_failed", error=str(e))
        return results

    _TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE)

    async def _process_single_url(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "url": url,
            "status": "unknown",
            "redirect": "",
            "final_url": url,
            "response_time_ms": 0,
            "title": "",
            "server": "",
            "content_type": "",
        }
        try:
            start = asyncio.get_event_loop().time()
            async with session.get(url, allow_redirects=False) as response:
                info["status"] = response.status
                info["response_time_ms"] = int((asyncio.get_event_loop().time() - start) * 1000)
                info["server"] = response.headers.get("server", "")
                info["content_type"] = response.headers.get("content-type", "")

                if response.status in (301, 302, 303, 307, 308):
                    redirect_location = response.headers.get("location", "")
                    if redirect_location:
                        if redirect_location.startswith("/"):
                            redirect_location = urljoin(url, redirect_location)
                        info["redirect"] = redirect_location
                        info["final_url"] = redirect_location

                if response.status == 200 and "text/html" in info["content_type"].lower():
                    try:
                        content = await response.text(errors="ignore")
                        match = self._TITLE_RE.search(content)
                        if match:
                            info["title"] = match.group(1).strip()
                    except Exception:
                        pass
        except asyncio.TimeoutError:
            info["status"] = "timeout"
        except aiohttp.ClientError as e:
            info["status"] = f"error: {str(e)[:50]}"
        except Exception as e:
            info["status"] = f"unknown_error: {str(e)[:50]}"
        return info

    def _classify_vulnerabilities(
        self, url_data: List[Dict[str, Any]], scan_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Classify URLs as clean or virus based on scan findings and heuristics."""
        vuln_urls = set()
        for finding_type in (
            "header_findings", "nuclei_findings", "threat_findings",
            "js_secrets", "plugin_findings",
        ):
            for finding in scan_results.get(finding_type, []) or []:
                if finding.get("url"):
                    vuln_urls.add(finding["url"])

        for info in url_data:
            url = info["url"]
            classification = "clean"
            if url in vuln_urls:
                classification = "virus"
            elif self._is_suspicious_url(url):
                classification = "virus"
            elif self._is_suspicious_response(info):
                classification = "virus"
            info["classification"] = classification
        return url_data

    def _is_suspicious_url(self, url: str) -> bool:
        return any(p.search(url) for p in self._compiled_suspicious)

    def _is_suspicious_response(self, info: Dict[str, Any]) -> bool:
        status = info.get("status")
        if isinstance(status, int) and status >= 500:
            return True
        server = (info.get("server") or "").lower()
        if any(s in server for s in ("hack", "exploit", "malware")):
            return True
        title = (info.get("title") or "").lower()
        if any(s in title for s in ("hacked", "defaced", "malware", "virus")):
            return True
        return False

    def _generate_report_file(self, url_data: List[Dict[str, Any]]) -> Path:
        """Write report file in the required format and return its path."""
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        clean_domain = re.sub(r"[^\w\-.]", "_", self.domain)
        filename = f"{clean_domain}_report_{timestamp}.txt"
        report_path = self.output_dir / filename

        sorted_data = sorted(
            url_data,
            key=lambda x: (0 if x.get("classification") == "virus" else 1, x.get("url", "")),
        )

        clean_count = sum(1 for x in url_data if x.get("classification") == "clean")
        virus_count = sum(1 for x in url_data if x.get("classification") == "virus")

        lines: List[str] = []
        lines.append("=" * 100)
        lines.append("ENHANCED SITEMAP VULNERABILITY REPORT")
        lines.append("=" * 100)
        lines.append(f"Target Domain : {self.domain}")
        lines.append(f"Scan Date     : {now.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total URLs    : {len(url_data)}")
        lines.append(f"Clean URLs    : {clean_count}")
        lines.append(f"Vulnerable    : {virus_count}")
        lines.append("=" * 100)
        lines.append("")
        lines.append("FORMAT: URL | Status | Classification | Redirect")
        lines.append("-" * 100)

        for info in sorted_data:
            status = info.get("status")
            status_str = str(status)[:20]
            classification = info.get("classification", "clean")
            redirect = info.get("redirect") or "none"
            url = info.get("url", "")

            display_url = url if len(url) <= 80 else url[:77] + "..."
            display_redirect = redirect if len(redirect) <= 80 else redirect[:77] + "..."

            lines.append(f"{display_url:<80} | {status_str:<10} | {classification:<10} | {display_redirect}")

        lines.append("")
        lines.append("-" * 100)
        lines.append("LEGEND:")
        lines.append("  Status         : HTTP status code or error description")
        lines.append("  Classification : 'clean' = no vulnerabilities, 'virus' = vulnerabilities detected")
        lines.append("  Redirect       : target URL if redirect detected, 'none' otherwise")
        lines.append("-" * 100)
        lines.append("Report generated by SiteMap Guard Enhanced Reporter v4.0")
        lines.append(f"Timestamp: {now.isoformat()}")
        lines.append("=" * 100)

        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path
