"""
Core execution pipeline orchestrating external binaries (Nuclei, httpx, ffuf)
and sitemap discovery — with resilient SSL bypass, DNS recon, and
requests-based fallbacks for broken-TLS targets.
"""
import os
import re
import ssl
import json
import asyncio
import requests
import urllib3
from typing import List, Dict, Any, Optional
from pathlib import Path
from requests.adapters import HTTPAdapter
import structlog
from usp.tree import sitemap_tree_for_homepage

from sitemap_guard.config import get_settings
from sitemap_guard.utils.threat_feeds import ThreatFeedManager
from sitemap_guard.scanner.headers import HeaderScanner
from sitemap_guard.utils.probe import fallback_probe, _FINGERPRINTER, _extract_title
from sitemap_guard.utils.dns_recon import run_dns_recon
from sitemap_guard.utils.passive_recon import run_passive_recon
from sitemap_guard.utils.js_scanner import scan_for_secrets
from sitemap_guard.storage.db import save_scan, get_diff
from sitemap_guard.plugins import run_all_plugins


class _LegacySSLAdapter(HTTPAdapter):
    """Requests adapter with legacy SSL support for UNEXPECTED_EOF servers."""
    def _make_ctx(self):
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

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._make_ctx()
        super().init_poolmanager(*args, **kwargs)


def _make_session() -> requests.Session:
    s = requests.Session()
    a = _LegacySSLAdapter(max_retries=1)
    s.mount("https://", a)
    s.mount("http://", a)
    return s

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = structlog.get_logger()

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# Extended common path list for thorough discovery
COMMON_PATHS = [
    # Secrets & config
    ".git/config", ".git/HEAD", ".gitignore", ".env", ".env.backup", ".env.local",
    ".env.production", ".env.staging", ".env.example", "config.php", "config.json",
    "config.yml", "config.yaml", "config.xml", "settings.py", "settings.php",
    "database.yml", "database.sql", "db.sqlite", "db.sql", "dump.sql", "backup.sql",
    "web.config", "app.config", "application.properties", "application.yml",
    ".htaccess", ".htpasswd", "php.ini",
    # Dev files
    "package.json", "package-lock.json", "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock", "requirements.txt", "Pipfile", "yarn.lock",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore",
    "Makefile", "Jenkinsfile", "Vagrantfile", ".travis.yml", ".circleci/config.yml",
    "README.md", "CHANGELOG.md", "RELEASE.md", "TODO.md",
    # Admin panels
    "admin/", "admin/login", "administrator/", "wp-admin/", "wp-login.php",
    "wp-config.php", "wp-config.php.bak", "login.php", "signin.php", "auth.php",
    "panel/", "cpanel/", "dashboard/", "manage/", "control/", "backend/",
    # API & Docs
    "api/", "api/v1/", "api/v2/", "api/swagger.json", "api/swagger.yaml",
    "swagger-ui.html", "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "graphql", "graphiql", "api-docs", "docs/api",
    # PHP/Common scripts
    "phpinfo.php", "info.php", "test.php", "setup.php", "install.php",
    "xmlrpc.php", "xmlrpc_server.php", "shell.php", "cmd.php",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "web.tar.gz",
    # Sensitive paths
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/authorized_keys",
    "server-status", "server-info", "status", "health", "healthz",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/.DS_Store", "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt", "/.well-known/change-password",
]


def _requests_get(url: str, timeout: int = 12) -> Optional[requests.Response]:
    """Resilient requests GET using legacy SSL adapter."""
    try:
        session = _make_session()
        resp = session.get(
            url,
            headers=_BROWSER_HEADERS,
            timeout=(8, timeout),
            verify=False,
            allow_redirects=True,
        )
        return resp
    except Exception as e:
        logger.debug("pipeline.requests_failed", url=url, error=str(e))
        return None


def _discover_from_robots(base_url: str) -> List[str]:
    """Parse robots.txt and extract Sitemap: directives + disallowed paths."""
    found = []
    resp = _requests_get(f"{base_url.rstrip('/')}/robots.txt")
    if resp and resp.status_code == 200:
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                found.append(sitemap_url)
            elif line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and "*" not in path:
                    found.append(f"{base_url.rstrip('/')}{path}")
    return found


def _discover_from_sitemap_xml(base_url: str) -> List[str]:
    """Directly fetch and parse sitemap.xml via requests (handles SSL issues USP can't)."""
    found = []
    sitemap_urls = [
        f"{base_url.rstrip('/')}/sitemap.xml",
        f"{base_url.rstrip('/')}/sitemap_index.xml",
        f"{base_url.rstrip('/')}/sitemap-index.xml",
        f"{base_url.rstrip('/')}/wp-sitemap.xml",
    ]
    for s_url in sitemap_urls:
        resp = _requests_get(s_url)
        if not resp or resp.status_code != 200:
            continue
        content_type = resp.headers.get("content-type", "")
        if "html" in content_type.lower():
            continue  # Skip HTML responses masquerading as sitemap
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(resp.content)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            # Try sitemap index
            for loc in root.findall(".//sm:loc", ns):
                if loc.text:
                    found.append(loc.text.strip())
            # Fallback without namespace
            for loc in root.findall(".//loc"):
                if loc.text:
                    found.append(loc.text.strip())
        except Exception as e:
            logger.debug("pipeline.sitemap_parse_failed", url=s_url, error=str(e))
    return found


class BugBountyPipeline:
    def __init__(self, target_url: str, output_dir: str = "./reports"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.bin_dir = Path(__file__).parent.parent / "bin"

        # Binaries
        self.httpx_bin = str(self.bin_dir / ("httpx.exe" if os.name == "nt" else "httpx"))
        self.nuclei_bin = str(self.bin_dir / ("nuclei.exe" if os.name == "nt" else "nuclei"))
        self.ffuf_bin = str(self.bin_dir / ("ffuf.exe" if os.name == "nt" else "ffuf"))

        # Config & Utilities
        self.settings = get_settings()
        self.threat_manager = ThreatFeedManager(
            cache_dir=self.settings.threat_feed_cache_dir,
            capacity=self.settings.bloom_filter_capacity
        )

    async def run(self) -> Dict[str, Any]:
        """Run the full pipeline."""
        logger.info("pipeline.start", target=self.target_url)

        # 0. DNS Recon (parallel with discovery)
        dns_task = asyncio.create_task(run_dns_recon(self.target_url))
        passive_task = asyncio.create_task(run_passive_recon(self.target_url))

        # 1. Discovery
        urls = await self.discover_urls()
        
        # 1.5 Add passive URLs
        passive_urls = await passive_task
        urls.extend(passive_urls)
        
        logger.info("pipeline.discovered", count=len(urls))

        # 2. Filtering
        filtered_urls = self.filter_urls(urls)
        logger.info("pipeline.filtered", count=len(filtered_urls))

        # Write to file for binaries
        target_file = self.output_dir / "targets.txt"
        with open(target_file, "w") as f:
            for url in filtered_urls:
                f.write(url + "\n")

        # 3. HTTP Probing
        live_targets = await self.probe_httpx(str(target_file))
        blocked_targets = [t for t in live_targets if self._is_cloudflare_block(t)]
        for t in blocked_targets:
            t["blocked"] = "cloudflare_403"
        scannable_targets = [t for t in live_targets if t not in blocked_targets]
        logger.info(
            "pipeline.probed",
            live_count=len(live_targets),
            scannable_count=len(scannable_targets),
            blocked_count=len(blocked_targets)
        )

        # Fallback: If probing fails but we have URLs, use requests-based direct probing
        if not scannable_targets and filtered_urls:
            if blocked_targets:
                logger.warning("pipeline.cloudflare_blocked",
                               msg="All candidates were blocked by Cloudflare (403).")
            else:
                logger.warning("pipeline.probe_fallback",
                               msg="httpx found no live hosts, running deep Python fallback probe.")
                live_targets = await fallback_probe(filtered_urls, target_url=self.target_url, concurrency=15)
                if not live_targets:
                    # Last resort: mark as discovery fallback so scanning still happens
                    logger.warning("pipeline.using_discovery_fallback",
                                   msg="All probes failed — using discovery list directly.")
                    live_targets = [
                        {"url": u, "status": 0, "title": "Discovery Fallback", "tech": []}
                        for u in filtered_urls
                    ]
                scannable_targets = live_targets

        # Enrich live targets with requests-based data if status == 0
        scannable_targets = await self._enrich_targets(scannable_targets)

        live_file = self.output_dir / "live_targets.txt"
        with open(live_file, "w") as f:
            for t in scannable_targets:
                f.write(t["url"] + "\n")

        # 3.5 Header Scan (only root URL + a sample to avoid noise)
        sample_urls = self._select_scan_sample(scannable_targets, max_urls=50)
        header_scanner = HeaderScanner()
        header_findings = await header_scanner.scan_urls(sample_urls, concurrency=8)
        logger.info("pipeline.headers", findings=len(header_findings))

        # 4. Nuclei Scan
        nuclei_results = await self.run_nuclei(str(live_file))
        logger.info("pipeline.nuclei", findings=len(nuclei_results))

        # 5. Local Threat Scan (Offline)
        threat_findings = []
        if self.settings.enable_offline_threats:
            await self.threat_manager.load_feeds(self.settings.threat_feed_urls)
            for url in filtered_urls:
                if self.threat_manager.is_malicious(url):
                    threat_findings.append({
                        "url": url,
                        "type": "malicious_reputation",
                        "severity": "high",
                        "source": "local_threat_feeds"
                    })
            logger.info("pipeline.threat_scan", findings=len(threat_findings))

        # 6. JS Secret Harvester
        js_secrets = await scan_for_secrets(scannable_targets, concurrency=10)

        # 7. Await DNS recon
        dns_info = await dns_task
        
        # 8. Plugins
        plugin_findings = await run_all_plugins(self.target_url, scannable_targets, dns_info)
        
        # Combine all findings for DB storage
        all_findings = header_findings + nuclei_results + threat_findings + js_secrets + plugin_findings
        db_path = str(self.output_dir.parent / "sitemap_guard_v4.db")
        scan_id = await save_scan(self.target_url, scannable_targets, all_findings, db_path)
        diff = await get_diff(self.target_url, scannable_targets, all_findings, db_path)

        return {
            "target": self.target_url,
            "scan_id": scan_id,
            "live_targets": scannable_targets,
            "header_findings": header_findings,
            "nuclei_findings": nuclei_results,
            "threat_findings": threat_findings,
            "js_secrets": js_secrets,
            "plugin_findings": plugin_findings,
            "dns_info": dns_info,
            "diff": diff,
        }

    async def _enrich_targets(self, targets: List[Dict]) -> List[Dict]:
        """
        For any target with status==0, attempt a direct requests probe
        in a thread pool to get real status, title, and tech stack.
        """
        async def _enrich_one(t: Dict) -> Dict:
            if t.get("status", 0) != 0:
                return t
            enriched = await asyncio.to_thread(_requests_get, t["url"])
            if enriched and enriched.status_code:
                from sitemap_guard.utils.probe import _FINGERPRINTER, _extract_title
                body = enriched.text
                hdrs = {k.lower(): v for k, v in enriched.headers.items()}
                tech = _FINGERPRINTER.detect(hdrs, body)
                title = _extract_title(body)
                t["status"] = enriched.status_code
                t["title"] = title or t.get("title", "")
                t["tech"] = tech
                t["headers"] = dict(hdrs)
            return t

        enriched = await asyncio.gather(*[_enrich_one(t) for t in targets], return_exceptions=True)
        return [t for t in enriched if isinstance(t, dict)]

    def _select_scan_sample(self, targets: List[Dict], max_urls: int = 50) -> List[str]:
        """Pick a representative sample: root URL first, then de-duped paths."""
        urls = [t["url"] for t in targets]
        # Root URL always first
        root = self.target_url.rstrip("/") + "/"
        ordered = [u for u in urls if u == root or u == self.target_url]
        ordered += [u for u in urls if u not in ordered]
        return ordered[:max_urls]

    async def discover_urls(self) -> List[str]:
        """
        Multi-strategy discovery:
        1. requests-based robots.txt parsing (SSL bypass)
        2. requests-based sitemap.xml parsing (SSL bypass)
        3. USP library (best-effort, timeout-guarded)
        4. 80+ common path probes
        5. Katana JS crawl (if binary present)
        """
        urls: set[str] = set()
        urls.add(self.target_url)

        base = self.target_url.rstrip("/")

        # --- Strategy 1: robots.txt (fast, requests-based) ---
        try:
            robots_urls = await asyncio.to_thread(_discover_from_robots, base)
            urls.update(robots_urls)
            logger.info("discovery.robots", count=len(robots_urls))
        except Exception as e:
            logger.debug("discovery.robots_failed", error=str(e))

        # --- Strategy 2: Direct sitemap.xml fetch (requests, SSL bypass) ---
        try:
            sitemap_urls = await asyncio.to_thread(_discover_from_sitemap_xml, base)
            urls.update(sitemap_urls)
            logger.info("discovery.sitemap_direct", count=len(sitemap_urls))
        except Exception as e:
            logger.debug("discovery.sitemap_direct_failed", error=str(e))

        # --- Strategy 3: USP library (best-effort) ---
        def _usp_parse():
            try:
                import requests as req
                original_get = req.get
                def fast_get(*args, **kwargs):
                    kwargs.setdefault("timeout", 5)
                    kwargs.setdefault("verify", False)
                    return original_get(*args, **kwargs)
                req.get = fast_get
                tree = sitemap_tree_for_homepage(self.target_url)
                return {page.url for page in tree.all_pages()}
            except Exception as e:
                logger.debug("discovery.usp_failed", error=str(e))
                return set()

        try:
            usp_urls = await asyncio.wait_for(asyncio.to_thread(_usp_parse), timeout=15.0)
            urls.update(usp_urls)
            if usp_urls:
                logger.info("discovery.usp", count=len(usp_urls))
        except asyncio.TimeoutError:
            logger.warning("discovery.sitemap_timeout",
                           msg="Sitemap parsing took too long, skipping.")
        except Exception as e:
            logger.warning("discovery.sitemap_error", error=str(e))

        # --- Strategy 4: Common path probes + Tech-Aware Wordlists ---
        # Initial probe of root to get tech
        root_resp = await asyncio.to_thread(_requests_get, self.target_url)
        tech_detected = []
        if root_resp and root_resp.status_code:
            tech_detected = _FINGERPRINTER.detect(
                {k.lower(): v for k, v in root_resp.headers.items()}, 
                root_resp.text
            )
            
        tech_paths = []
        tech_lower = [t.lower() for t in tech_detected]
        if any("wordpress" in t for t in tech_lower):
            tech_paths.extend(["wp-config.php.bak", "wp-content/debug.log", "xmlrpc.php", "wp-cron.php"])
        if any("laravel" in t for t in tech_lower):
            tech_paths.extend([".env", "storage/logs/laravel.log", "public/storage/"])
        if any("django" in t for t in tech_lower):
            tech_paths.extend(["admin/", "__debug__/", "api/schema/", "static/admin/"])
        if any("iis" in t or "asp.net" in t for t in tech_lower):
            tech_paths.extend(["web.config", "Trace.axd", "elmah.axd", "ScriptResource.axd"])
        if any("spring" in t for t in tech_lower):
            tech_paths.extend(["/actuator", "/actuator/env", "/actuator/heapdump", "/h2-console"])
        if any("drupal" in t for t in tech_lower):
            tech_paths.extend(["sites/default/settings.php", "update.php", "install.php"])
            
        if tech_paths:
            logger.info("discovery.tech_paths", count=len(tech_paths), tech=tech_detected)

        for path in COMMON_PATHS + tech_paths:
            urls.add(f"{base}/{path.lstrip('/')}")

        # --- Strategy 5: Katana JS Crawl ---
        katana_bin = str(self.bin_dir / ("katana.exe" if os.name == "nt" else "katana"))
        if os.path.exists(katana_bin):
            logger.info("discovery.katana", msg="Starting Katana JS Crawl")
            katana_cmd = [katana_bin, "-u", self.target_url, "-jc", "-d", "3", "-silent"]
            try:
                process = await asyncio.create_subprocess_exec(
                    *katana_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=30.0)
                if stdout:
                    for line in stdout.decode("utf-8").splitlines():
                        if line.strip().startswith("http"):
                            urls.add(line.strip())
            except asyncio.TimeoutError:
                try:
                    process.kill()
                except Exception:
                    pass
                logger.warning("discovery.katana_timeout", msg="Katana crawl timed out")
            except Exception as e:
                logger.warning("discovery.katana_error", error=str(e))
        else:
            logger.debug("discovery.katana_missing", path=katana_bin)

        return list(urls)

    def filter_urls(self, urls: List[str]) -> List[str]:
        """Filter and deduplicate URLs — strip static assets."""
        ignore_exts = {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico",
            ".css", ".js", ".svg", ".woff", ".woff2", ".ttf", ".eot",
            ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".doc", ".docx",
            ".xls", ".xlsx", ".ppt", ".pptx",
        }
        filtered = set()
        for url in urls:
            url_lower = url.lower().split("?")[0]
            if any(url_lower.endswith(ext) for ext in ignore_exts):
                continue
            filtered.add(url)
        return list(filtered)

    def _is_cloudflare_block(self, target: Dict[str, Any]) -> bool:
        if target.get("status") != 403:
            return False
        tech = [t.lower() for t in target.get("tech", []) if isinstance(t, str)]
        if any("cloudflare" in t for t in tech):
            return True
        title = (target.get("title") or "").lower()
        return "just a moment" in title or "attention required" in title

    async def probe_httpx(self, target_file: str) -> List[Dict]:
        """Run PD httpx to find live hosts. Falls back to Python probe if missing/fails."""
        results = []
        urls = []
        if os.path.exists(target_file):
            with open(target_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]

        if not os.path.exists(self.httpx_bin):
            logger.warning("pipeline.httpx_missing",
                           msg="Httpx binary missing. Falling back to Python probe.",
                           path=self.httpx_bin)
            return await fallback_probe(urls)

        output_file = self.output_dir / "httpx_out.json"
        cmd = [
            self.httpx_bin,
            "-l", target_file,
            "-json",
            "-o", str(output_file),
            "-silent",
            "-nc",
            "-tlsi",
            "-t", "50",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)

            if output_file.exists():
                with open(output_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                results.append({
                                    "url": data.get("url"),
                                    "status": data.get("status_code"),
                                    "title": data.get("title", ""),
                                    "tech": data.get("tech", [])
                                })
                            except Exception:
                                pass
        except Exception as e:
            logger.warning("pipeline.httpx_failed", error=str(e))

        if not results:
            logger.info("pipeline.httpx_fallback",
                        msg="No results from httpx, launching python fallback")
            results = await fallback_probe(urls)

        return results

    async def run_nuclei(self, target_file: str) -> List[Dict]:
        """Run Nuclei against live targets in chunks."""
        if not os.path.exists(self.nuclei_bin):
            logger.warning("pipeline.nuclei_missing", path=self.nuclei_bin)
            return []

        output_file = self.output_dir / "nuclei_out.json"
        targets = []
        with open(target_file, "r") as f:
            targets = [l.strip() for l in f if l.strip()]

        if not targets:
            return []

        chunk_size = 50
        chunks = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]
        all_results = []
        seen = set()

        for i, chunk in enumerate(chunks):
            logger.info("pipeline.nuclei_chunk", chunk=i + 1, total=len(chunks), size=len(chunk))

            chunk_file = self.output_dir / f"chunk_{i}.txt"
            with open(chunk_file, "w") as f:
                f.write("\n".join(chunk))

            chunk_out = self.output_dir / f"nuclei_chunk_{i}.json"
            cmd = [
                self.nuclei_bin,
                "-l", str(chunk_file),
                "-json-export", str(chunk_out),
                "-silent", "-nc", "-tlsi", "-ni",
                "-c", "50",
                "-etags", "intrusive,dos,fuzz,fuzzing",
                "-s", "low,medium,high,critical",
                "-retries", "1",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                logger.warning("pipeline.nuclei_timeout", chunk=i + 1)
                try:
                    proc.kill()
                except Exception:
                    pass
            except Exception as e:
                logger.error("pipeline.nuclei_error", chunk=i + 1, error=str(e))

            if chunk_out.exists():
                with open(chunk_out, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                dedup_key = (
                                    finding.get("template-id"),
                                    finding.get("matched-at", finding.get("host"))
                                )
                                if dedup_key not in seen:
                                    seen.add(dedup_key)
                                    all_results.append(finding)
                            except Exception:
                                pass
                try:
                    chunk_out.unlink()
                except FileNotFoundError:
                    pass
            try:
                chunk_file.unlink()
            except FileNotFoundError:
                pass

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)

        return all_results
