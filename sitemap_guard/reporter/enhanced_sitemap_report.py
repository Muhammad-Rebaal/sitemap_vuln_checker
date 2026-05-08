"""
Enhanced sitemap reporter — plain-text report aligned with:
URL | Status | Classification | Redirect | Reason

Output filename: <domain>_report_<YYYYMMDD_HHMMSS>.txt
"""
import re
import asyncio
import ssl
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urldefrag, urljoin, urlparse

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

    # Skip downloading these in BFS (still probed later).
    _STATIC_SUFFIXES = frozenset(
        (
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".webp",
            ".ico",
            ".bmp",
            ".svg",
            ".css",
            ".js",
            ".mjs",
            ".map",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".otf",
            ".pdf",
            ".zip",
            ".gz",
            ".tar",
            ".mp4",
            ".mp3",
            ".wav",
            ".webm",
            ".avi",
            ".json",
            ".xml",
        )
    )

    _LOC_RE = re.compile(r"<loc>([^<]+)</loc>", re.IGNORECASE)

    def __init__(
        self,
        target_url: str,
        output_dir: str = "./reports",
        max_urls: int = 5000,
        include_external_assets: bool = False,
        workers: int = 96,
    ):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.domain = urlparse(self.target_url).netloc or self.target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_urls = max(0, int(max_urls))
        self.include_external_assets = include_external_assets
        self.workers = max(8, min(int(workers), 320))

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        self._compiled_suspicious = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_URL_PATTERNS]

    async def generate_enhanced_report(
        self,
        scan_results: Optional[Dict[str, Any]] = None,
        progress: Any = None,
    ) -> str:
        """
        Discover URLs (BFS + recursive sitemaps), probe in parallel, classify, write report.

        ``progress`` may be a Rich :class:`rich.progress.Progress` instance; when passed, the
        reporter adds/updates discovery and probe tasks.
        """
        scan_results = scan_results or {}
        logger.info("enhanced_reporter.starting", domain=self.domain)

        disc_task_id: Any = None
        probe_task_id: Any = None
        if progress is not None:
            disc_task_id = progress.add_task(
                "[bold cyan]Discovery[/] — BFS, sitemaps, robots…",
                total=None,
            )

        all_urls = await self._collect_all_urls(scan_results, progress, disc_task_id)
        all_urls = self._dedupe_cap_urls(all_urls)

        if progress is not None and disc_task_id is not None:
            progress.update(
                disc_task_id,
                total=1,
                completed=1,
                description=f"[bold cyan]Discovery done[/] — {len(all_urls)} URL(s)",
            )

        if progress is not None:
            probe_task_id = progress.add_task(
                "[bold green]Probe URLs[/] — status & classification",
                total=len(all_urls),
            )

        url_data = await self._process_urls(all_urls, progress, probe_task_id)
        classified_data = self._classify_vulnerabilities(url_data, scan_results)
        finding_msgs = self._finding_messages_by_url(scan_results)
        self._attach_reasons(classified_data, finding_msgs)
        report_path = self._generate_report_file(classified_data)

        if progress is not None and probe_task_id is not None:
            progress.update(
                probe_task_id,
                completed=len(all_urls),
                description="[bold green]Probe complete[/]",
            )

        logger.info(
            "enhanced_reporter.completed",
            report_path=str(report_path),
            total_urls=len(classified_data),
        )
        return str(report_path)

    def _normalize_url(self, url: str) -> str:
        u, _frag = urldefrag(url.strip())
        return u

    def _same_host(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        if not host or not self.domain:
            return False
        base = self.domain.lower()
        return host == base or host.endswith("." + base)

    def _path_suffix(self, url: str) -> str:
        p = urlparse(url).path.lower().rsplit("/", 1)[-1]
        if "." in p:
            return "." + p.split(".")[-1]
        return ""

    def _should_fetch_html_body(self, url: str) -> bool:
        suf = self._path_suffix(url)
        if suf in self._STATIC_SUFFIXES:
            return False
        return True

    async def _collect_all_urls(
        self,
        scan_results: Dict[str, Any],
        progress: Any = None,
        disc_task_id: Any = None,
    ) -> List[str]:
        """Merge pipeline URLs + robots/sitemaps + common paths + same-host BFS."""
        all_urls: Set[str] = set()

        def add_url(u: Optional[str]) -> None:
            if not u:
                return
            nu = self._normalize_url(u)
            if self._same_host(nu):
                all_urls.add(nu)

        add_url(self.target_url)

        for target in scan_results.get("live_targets", []) or []:
            add_url(target.get("url"))

        for key in ("urls", "discovered_urls"):
            for u in scan_results.get(key, []) or []:
                add_url(u)

        conn_limit = max(32, self.workers + 8)
        async with self._make_session(timeout=25, limit=conn_limit) as session:
            hints, sitemap_roots = await self._parse_robots_txt_split(session)
            for h in hints:
                add_url(h)

            seed_sitemaps = [
                f"{self.target_url}/sitemap.xml",
                f"{self.target_url}/sitemap_index.xml",
                f"{self.target_url}/sitemap-index.xml",
                f"{self.target_url}/wp-sitemap.xml",
                f"{self.target_url}/sitemap1.xml",
                f"{self.target_url}/sitemaps.xml",
            ]
            roots_ordered = list(dict.fromkeys([*seed_sitemaps, *sitemap_roots]))

            locs = await self._recursive_sitemap(session, roots_ordered)
            for loc in locs:
                add_url(loc)

            for cu in self._common_path_urls():
                add_url(cu)

            await self._bfs_discover_links(
                session,
                all_urls,
                progress,
                disc_task_id,
            )

        return list(all_urls)

    async def _parse_robots_txt_split(
        self, session: aiohttp.ClientSession
    ) -> Tuple[List[str], List[str]]:
        """Return (same-host path hints, sitemap XML URLs)."""
        page_hints: List[str] = []
        sitemap_roots: List[str] = []
        robots_url = f"{self.target_url}/robots.txt"
        try:
            async with session.get(robots_url) as response:
                if response.status != 200:
                    return page_hints, sitemap_roots
                content = await response.text()
                for line in content.splitlines():
                    line = line.strip()
                    low = line.lower()
                    if low.startswith("sitemap:"):
                        sm = line.split(":", 1)[1].strip()
                        if sm:
                            sitemap_roots.append(sm)
                    elif low.startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and "*" not in path:
                            page_hints.append(
                                urljoin(self.target_url + "/", path.lstrip("/"))
                            )
        except Exception as e:
            logger.debug("robots_parse_failed", error=str(e))
        return page_hints, sitemap_roots

    async def _recursive_sitemap(
        self,
        session: aiohttp.ClientSession,
        roots: List[str],
        max_sitemap_documents: int = 200,
    ) -> List[str]:
        """Follow sitemap indexes and collect <loc> page URLs."""
        seen_docs: Set[str] = set()
        out_locs: List[str] = []
        fetches = 0

        async def walk(sm_url: str) -> None:
            nonlocal fetches
            if (
                not sm_url
                or sm_url in seen_docs
                or fetches >= max_sitemap_documents
                or len(out_locs) > (self.max_urls or 999999) * 50
            ):
                return
            seen_docs.add(sm_url)
            fetches += 1
            try:
                async with session.get(sm_url, allow_redirects=True) as response:
                    if response.status != 200:
                        return
                    text = await response.text(errors="ignore")
            except Exception as e:
                logger.debug("sitemap_fetch_failed", url=sm_url, error=str(e))
                return

            low = text.lower()
            if "sitemapindex" in low or "<sitemap>" in low:
                for loc in self._LOC_RE.findall(text):
                    loc_u = loc.strip()
                    if loc_u:
                        await walk(loc_u)
            else:
                for loc in self._LOC_RE.findall(text):
                    loc_u = loc.strip()
                    if loc_u:
                        out_locs.append(loc_u)

        for root in roots:
            await walk(root)
        return out_locs

    async def _bfs_discover_links(
        self,
        session: aiohttp.ClientSession,
        all_urls: Set[str],
        progress: Any = None,
        disc_task_id: Any = None,
    ) -> None:
        """Breadth-first crawl: fetch HTML-like pages and enqueue new same-host URLs."""
        batch_size = max(8, min(self.workers, 48))
        q: deque[str] = deque(
            sorted(u for u in all_urls if self._should_fetch_html_body(u))
        )
        fetched: Set[str] = set()

        def tick() -> None:
            if progress is None or disc_task_id is None:
                return
            desc = (
                f"[bold cyan]Discovery[/] — {len(all_urls)} URL(s), "
                f"{len(fetched)} page(s) expanded"
            )
            if self.max_urls:
                progress.update(
                    disc_task_id,
                    description=desc,
                    completed=min(len(all_urls), self.max_urls),
                    total=self.max_urls,
                )
            else:
                progress.update(disc_task_id, description=desc)

        tick()
        while q and (not self.max_urls or len(all_urls) < self.max_urls):
            batch: List[str] = []
            while q and len(batch) < batch_size:
                u = q.popleft()
                nu = self._normalize_url(u)
                if not self._same_host(nu) or nu in fetched:
                    continue
                if not self._should_fetch_html_body(nu):
                    fetched.add(nu)
                    continue
                fetched.add(nu)
                batch.append(nu)
            if not batch:
                if not q:
                    break
                tick()
                continue

            async def one(u: str) -> List[str]:
                return await self._fetch_html_extract_links(session, u)

            chunks = await asyncio.gather(*[one(u) for u in batch], return_exceptions=True)
            for chunk in chunks:
                if isinstance(chunk, Exception):
                    continue
                for link in chunk:
                    nl = self._normalize_url(link)
                    if not self._same_host(nl):
                        continue
                    if nl not in all_urls and (not self.max_urls or len(all_urls) < self.max_urls):
                        all_urls.add(nl)
                        if self._should_fetch_html_body(nl):
                            q.append(nl)
            tick()

    async def _fetch_html_extract_links(
        self, session: aiohttp.ClientSession, url: str
    ) -> List[str]:
        try:
            async with session.get(
                url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as response:
                ctype = (response.headers.get("content-type") or "").lower()
                if response.status != 200 or "html" not in ctype:
                    return []
                text = await response.text(errors="ignore")
                base = str(response.url)
        except Exception as e:
            logger.debug("bfs_fetch_failed", url=url, error=str(e))
            return []
        return self._extract_links_from_html(text, base)

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

    def _make_session(
        self, timeout: int = 10, limit: Optional[int] = None
    ) -> aiohttp.ClientSession:
        lim = limit if limit is not None else max(32, self.workers)
        return aiohttp.ClientSession(
            headers=self.DEFAULT_HEADERS,
            connector=aiohttp.TCPConnector(
                ssl=self.ssl_context,
                limit=lim,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
            ),
            timeout=aiohttp.ClientTimeout(total=timeout),
        )

    def _common_path_urls(self) -> List[str]:
        return [urljoin(self.target_url + "/", path.lstrip("/")) for path in self.COMMON_PATHS]

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
            if self._same_host(full_url):
                links.append(full_url)
            elif self.include_external_assets:
                path_only = full_url.split("?", 1)[0].lower()
                if any(path_only.endswith(suf) for suf in self._ASSET_SUFFIXES):
                    links.append(full_url)
        return links

    async def _process_urls(
        self,
        urls: List[str],
        progress: Any = None,
        probe_task_id: Any = None,
    ) -> List[Dict[str, Any]]:
        """Probe each URL with high concurrency; optional Rich progress advance."""
        results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(self.workers)
        conn_limit = max(32, self.workers + 8)
        async with self._make_session(timeout=22, limit=conn_limit) as session:

            async def bounded(url: str) -> Dict[str, Any]:
                async with sem:
                    res = await self._process_single_url(session, url)
                if progress is not None and probe_task_id is not None:
                    progress.advance(probe_task_id, 1)
                return res

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
            return (
                "No HTTP response from this scanner (DNS, TLS, firewall, rate-limit, or host "
                "unreachable). Not a malware verdict — check your network and retry."
            )

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

        conn_like = 0
        for row in url_data:
            st = row.get("status")
            if isinstance(st, str) and (
                st == "timeout"
                or st.lower().startswith("connection_error")
                or st.startswith("unknown_error")
            ):
                conn_like += 1
        if url_data and conn_like == len(url_data):
            lines.append(
                "NOTE: Every URL failed to connect from this machine — the site may be fine, "
                "but this scanner got no HTTP response (DNS/VPN/firewall/offline). "
                "This is not evidence of malware."
            )
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
