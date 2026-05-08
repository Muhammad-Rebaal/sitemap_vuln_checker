"""
Enhanced sitemap reporter — plain-text report aligned with:
URL | Status | Classification | Redirect | Reason

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


REPORT_VERSION = "v4.2"
_SEP = "=" * 100


class EnhancedSitemapReporter:
    """
    Enhanced reporter: discovery, probe, classify (clean / issue / virus), Reason column,
    domain-based filename (<domain>_report_<date_time>.txt).
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

    def __init__(
        self,
        target_url: str,
        output_dir: str = "./reports",
        max_urls: int = 5000,
        include_external_assets: bool = False,
    ):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.domain = urlparse(self.target_url).netloc or self.target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_urls = max(0, int(max_urls))
        self.include_external_assets = include_external_assets

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
        all_urls = self._dedupe_cap_urls(all_urls)
        url_data = await self._process_urls(all_urls)
        classified_data = self._classify_vulnerabilities(url_data, scan_results)
        finding_msgs = self._finding_messages_by_url(scan_results)
        self._attach_reasons(classified_data, finding_msgs)
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

    def _dedupe_cap_urls(self, urls: List[str]) -> List[str]:
        ordered: List[str] = []
        seen = set()
        for u in urls:
            if u and u not in seen:
                seen.add(u)
                ordered.append(u)
        if not self.max_urls or len(ordered) <= self.max_urls:
            return ordered
        head: List[str] = []
        if self.target_url in ordered:
            head.append(self.target_url)
        rest = [u for u in ordered if u != self.target_url][: max(0, self.max_urls - len(head))]
        return head + rest

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

    _ASSET_SUFFIXES = (".css", ".js", ".mjs", ".woff", ".woff2", ".map")

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
            if not parsed.netloc or not parsed.scheme.startswith("http"):
                continue
            same_host = parsed.netloc == self.domain or (
                bool(self.domain) and parsed.netloc.endswith("." + self.domain)
            )
            if same_host:
                links.append(full_url)
            elif self.include_external_assets:
                path_only = full_url.split("?", 1)[0].lower()
                if any(path_only.endswith(suf) for suf in self._ASSET_SUFFIXES):
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
            err = str(e).strip().replace("\n", " ")
            info["status"] = f"connection_error: {err[:120]}" if err else "connection_error"
        except Exception as e:
            err = str(e).strip().replace("\n", " ")
            info["status"] = f"unknown_error: {err[:120]}" if err else "unknown_error"
        return info

    @staticmethod
    def _finding_messages_by_url(scan_results: Dict[str, Any]) -> Dict[str, str]:
        """Build a short scanner/heuristic message per URL from pipeline results."""
        by_url: Dict[str, List[str]] = {}
        for key in (
            "nuclei_findings",
            "header_findings",
            "threat_findings",
            "js_secrets",
            "plugin_findings",
        ):
            for f in scan_results.get(key, []) or []:
                if not isinstance(f, dict):
                    continue
                u = f.get("url") or f.get("matched-at") or f.get("matched_at")
                if not u:
                    continue
                parts = []
                tid = f.get("template-id") or f.get("template_id")
                if tid:
                    parts.append(f"template={tid}")
                if f.get("name"):
                    parts.append(str(f["name"]))
                if f.get("type"):
                    parts.append(f"type={f['type']}")
                if f.get("matcher_name"):
                    parts.append(str(f["matcher_name"]))
                msg = "; ".join(parts) if parts else (
                    str(f.get("info") or f.get("description") or "scanner finding")
                )
                by_url.setdefault(str(u), []).append(msg[:240])

        return {u: " | ".join(msgs[:5]) for u, msgs in by_url.items()}

    def _redirect_column(self, info: Dict[str, Any]) -> str:
        st = info.get("status")
        if isinstance(st, str):
            low = st.lower()
            if st == "timeout" or low.startswith(
                ("connection_error", "error:", "unknown_error")
            ):
                return "none"
        if info.get("redirect"):
            return str(info["redirect"])
        return str(info.get("url", ""))

    @staticmethod
    def _format_status_cell(status: Any, width: int = 20) -> str:
        s = str(status) if status is not None else "unknown"
        if len(s) <= width:
            return f"{s:<{width}}"
        return f"{s[: width - 2]}.."

    def _row_reason(
        self,
        info: Dict[str, Any],
        classification: str,
        finding_msgs: Dict[str, str],
    ) -> str:
        url = info.get("url", "")
        st = info.get("status")

        if classification == "virus":
            if url in finding_msgs:
                return finding_msgs[url]
            if self._is_suspicious_url(url):
                return "URL matched suspicious pattern (automated heuristic)"
            return (
                "Automated heuristics flagged this row; verify with your security tooling"
            )

        if classification == "issue":
            if isinstance(st, int) and st >= 500:
                return (
                    f"HTTP {st} server error (availability); not a malware verdict alone"
                )
            return "Server or availability issue (5xx); not a malware verdict alone"

        if isinstance(st, int):
            if st == 200:
                return "No automated security flags for this URL"
            if st == 404:
                return "HTTP 404; no security heuristics triggered"
            if st == 403:
                return "HTTP 403 (authentication or forbidden; often expected)"
            if st == 401:
                return "HTTP 401 (authentication required; often expected)"
            if 300 <= st < 400:
                return (
                    "HTTP redirect; see Redirect column for target; "
                    "no security heuristics triggered"
                )
            if 400 <= st < 500:
                return f"HTTP {st}; no security heuristics triggered"
            return f"HTTP {st}; no security heuristics triggered"

        if st == "timeout":
            return "Request timed out; not a malware verdict alone"

        s = str(st)
        if s.startswith("connection_error") or s.startswith("error:") or s.startswith(
            "unknown_error"
        ):
            return "Connection failed (network/TLS/DNS); not a malware verdict"

        return "No automated security flags for this URL"

    def _attach_reasons(
        self, url_data: List[Dict[str, Any]], finding_msgs: Dict[str, str]
    ) -> None:
        for info in url_data:
            cl = info.get("classification", "clean")
            info["reason"] = self._row_reason(info, cl, finding_msgs)

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
                if not isinstance(finding, dict):
                    continue
                u = finding.get("url") or finding.get("matched-at") or finding.get("matched_at")
                if u:
                    vuln_urls.add(str(u))

        for info in url_data:
            url = info["url"]
            classification = "clean"
            status = info.get("status")
            if url in vuln_urls:
                classification = "virus"
            elif self._is_suspicious_url(url):
                classification = "virus"
            elif isinstance(status, int) and status >= 500:
                classification = "issue"
            elif self._is_suspicious_response(info):
                classification = "virus"
            info["classification"] = classification
        return url_data

    def _is_suspicious_url(self, url: str) -> bool:
        return any(p.search(url) for p in self._compiled_suspicious)

    def _is_suspicious_response(self, info: Dict[str, Any]) -> bool:
        server = (info.get("server") or "").lower()
        if any(s in server for s in ("hack", "exploit", "malware")):
            return True
        title = (info.get("title") or "").lower()
        if any(s in title for s in ("hacked", "defaced", "malware", "virus")):
            return True
        return False

    def _generate_report_file(self, url_data: List[Dict[str, Any]]) -> Path:
        """Write report file matching SiteMap Guard Enhanced Reporter v4.2 layout."""
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        clean_domain = re.sub(r"[^\w\-.]", "_", self.domain)
        filename = f"{clean_domain}_report_{timestamp}.txt"
        report_path = self.output_dir / filename

        sorted_data = sorted(url_data, key=lambda x: x.get("url", ""))

        issue_count = sum(1 for x in url_data if x.get("classification") == "issue")
        virus_count = sum(1 for x in url_data if x.get("classification") == "virus")
        clean_count = sum(1 for x in url_data if x.get("classification") == "clean")

        st_w = 20
        cl_w = 10
        url_w = max((len(x.get("url", "")) for x in sorted_data), default=30)
        url_w = min(max(url_w, 35), 90)
        redir_w = max((len(self._redirect_column(x)) for x in sorted_data), default=20)
        redir_w = min(max(redir_w, 35), 85)

        lines: List[str] = []
        lines.append(_SEP)
        lines.append("ENHANCED SITEMAP VULNERABILITY REPORT")
        lines.append(_SEP)
        lines.append(f"Target Domain : {self.domain}")
        lines.append(f"Scan Date     : {now.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total URLs    : {len(url_data)}")
        lines.append(f"Clean URLs    : {clean_count}")
        lines.append(f"Issue (5xx)   : {issue_count}")
        lines.append(f"Security      : {virus_count}")
        lines.append(_SEP)
        lines.append("")
        lines.append("FORMAT: URL | Status | Classification | Redirect | Reason")
        lines.append(
            "  URL      : exact URL that was probed (discovered on your host, from HTML, or optional externals)"
        )
        lines.append(
            "  Redirect : for 301/302/303/307/308, the Location target; for other responses, final/same URL;"
        )
        lines.append(
            "             'none' only when the request could not be completed (timeouts, errors)."
        )
        lines.append(
            "             Third-party rows (CDNs, GTM, etc.) appear only if you enabled external-asset probing;"
        )
        lines.append(
            "             they are not vulnerabilities — same 'clean' only means the URL responded."
        )
        lines.append("-" * 100)

        for info in sorted_data:
            url = info.get("url", "")
            classification = info.get("classification", "clean")
            reason = info.get("reason", "")
            redirect = self._redirect_column(info)
            status_cell = self._format_status_cell(info.get("status"), st_w)

            lines.append(
                f"{url:<{url_w}} | {status_cell} | {classification:<{cl_w}} | "
                f"{redirect:<{redir_w}} | {reason}"
            )

        lines.append("")
        lines.append("-" * 100)
        lines.append("LEGEND:")
        lines.append("  Status         : HTTP status code or error description")
        lines.append(
            "  Classification : clean = no security signals; issue = HTTP 5xx (availability, not malware);"
        )
        lines.append(
            "                   virus = scanner finding or strong heuristic (see Reason)"
        )
        lines.append(
            "  Redirect       : see FORMAT note above (Location vs final URL vs none on failure)"
        )
        lines.append(
            "  Reason         : scanner/heuristic text, or short note — 'clean' is not a malware verdict alone"
        )
        lines.append("-" * 100)
        lines.append(f"Report generated by SiteMap Guard Enhanced Reporter {REPORT_VERSION}")
        lines.append(f"Timestamp: {now.isoformat()}")
        lines.append(_SEP)

        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path
