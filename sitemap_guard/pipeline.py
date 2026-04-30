"""
Core execution pipeline orchestrating external binaries (Nuclei, httpx, ffuf)
and sitemap discovery.
"""
import os
import json
import asyncio
import subprocess
from typing import List, Dict, Any, AsyncGenerator
from pathlib import Path
import structlog
from usp.tree import sitemap_tree_for_homepage

from sitemap_guard.config import get_settings
from sitemap_guard.utils.threat_feeds import ThreatFeedManager
from sitemap_guard.scanner.headers import HeaderScanner
from sitemap_guard.utils.probe import fallback_probe

logger = structlog.get_logger()

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
        
        # 1. Discovery
        urls = await self.discover_urls()
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
        
        # Fallback: If probing fails but we have URLs, don't give up.
        if not scannable_targets and filtered_urls:
            if blocked_targets:
                logger.warning("pipeline.cloudflare_blocked", msg="All candidates were blocked by Cloudflare (403). Skipping live host fallback.")
            else:
                logger.warning("pipeline.probe_fallback", msg="No live hosts found by httpx, falling back to discovered URLs.")
                live_targets = [{"url": u, "status": 0, "title": "Discovery Fallback", "tech": []} for u in filtered_urls]
                scannable_targets = live_targets
        
        live_file = self.output_dir / "live_targets.txt"
        with open(live_file, "w") as f:
            for t in scannable_targets:
                f.write(t["url"] + "\n")
                
        # 3.5 Header Scan
        header_scanner = HeaderScanner()
        header_findings = await header_scanner.scan_urls([t["url"] for t in scannable_targets])
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
        
        return {
            "target": self.target_url,
            "live_targets": live_targets,
            "header_findings": header_findings,
            "nuclei_findings": nuclei_results,
            "threat_findings": threat_findings
        }

    async def discover_urls(self) -> List[str]:
        """Discovery phase: Sitemap, robots.txt, 30+ common path probes, and Katana JS Crawl."""
        urls = set()
        urls.add(self.target_url)
        
        # 1. Sitemap and Robots via USP
        def _parse():
            try:
                import requests
                original_get = requests.get
                def fast_get(*args, **kwargs):
                    kwargs['timeout'] = 3
                    return original_get(*args, **kwargs)
                requests.get = fast_get
                
                tree = sitemap_tree_for_homepage(self.target_url)
                res = set()
                for page in tree.all_pages():
                    res.add(page.url)
                return res
            except Exception as e:
                logger.warning("discovery.usp_failed", error=str(e))
                return set()
                
        try:
            sitemap_urls = await asyncio.wait_for(asyncio.to_thread(_parse), timeout=10.0)
            urls.update(sitemap_urls)
        except asyncio.TimeoutError:
            logger.warning("discovery.sitemap_timeout", msg="Sitemap parsing took too long, skipping.")
        except Exception as e:
            logger.warning("discovery.sitemap_error", error=str(e))
            
        # 2. 30+ Common Path Probes
        base = self.target_url.rstrip("/")
        common_paths = [
            ".git/config", ".env", ".env.backup", "api/swagger.json", "swagger-ui.html",
            "server-status", "admin/", "administrator/", "login.php", "wp-login.php",
            "xmlrpc.php", "phpinfo.php", "backup.zip", "test.php", "config.php",
            ".DS_Store", "package.json", "composer.json", "web.config", "database.sql",
            "db.sqlite", "info.php", "setup.php", "install.php", ".ssh/id_rsa",
            "Dockerfile", "docker-compose.yml", "Makefile", "Jenkinsfile", "README.md"
        ]
        for path in common_paths:
            urls.add(f"{base}/{path}")
            
        # 3. Katana JS Crawl
        katana_bin = str(self.bin_dir / ("katana.exe" if os.name == "nt" else "katana"))
        if os.path.exists(katana_bin):
            logger.info("discovery.katana", msg="Starting Katana JS Crawl")
            katana_cmd = [
                katana_bin, "-u", self.target_url,
                "-jc", "-d", "3", "-silent"
            ]
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
                if process:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                logger.warning("discovery.katana_timeout", msg="Katana crawl timed out")
            except Exception as e:
                logger.warning("discovery.katana_error", error=str(e))
        else:
            logger.warning("discovery.katana_missing", path=katana_bin)
            
        return list(urls)

    def filter_urls(self, urls: List[str]) -> List[str]:
        """Custom logic to filter and deduplicate URLs."""
        # Strip static extensions
        ignore_exts = {".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".svg", ".woff", ".woff2", ".ttf", ".pdf"}
        filtered = set()
        
        for url in urls:
            url_lower = url.lower()
            if any(url_lower.endswith(ext) for ext in ignore_exts):
                continue
            filtered.add(url)
            
        return list(filtered)

    def _is_cloudflare_block(self, target: Dict[str, Any]) -> bool:
        status = target.get("status")
        if status != 403:
            return False
        tech = [t.lower() for t in target.get("tech", []) if isinstance(t, str)]
        if any("cloudflare" in t for t in tech):
            return True
        title = (target.get("title") or "").lower()
        return "just a moment" in title or "attention required" in title

    async def probe_httpx(self, target_file: str) -> List[Dict]:
        """Run PD httpx to find live hosts and get titles. Uses Pure Python fallback if httpx is missing or fails."""
        results = []
        urls = []
        if os.path.exists(target_file):
            with open(target_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]

        if not os.path.exists(self.httpx_bin):
            logger.warning("pipeline.httpx_missing", msg="Httpx binary missing. Falling back to Pure Python probe.", path=self.httpx_bin)
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
            "-t", "50" # High concurrency for speed
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=300) # 5m timeout
            
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
            logger.warning("pipeline.httpx_failed", error=str(e), msg="Falling back to Pure Python probe")
            
        if not results:
            logger.info("pipeline.httpx_fallback", msg="No results from httpx, launching python fallback")
            results = await fallback_probe(urls)
            
        return results

    async def run_nuclei(self, target_file: str) -> List[Dict]:
        """Run Nuclei against live targets in chunks to avoid blocking/DOS."""
        if not os.path.exists(self.nuclei_bin):
            logger.warning("pipeline.nuclei_missing", path=self.nuclei_bin)
            return []
            
        output_file = self.output_dir / "nuclei_out.json"
        
        # Load targets
        targets = []
        with open(target_file, "r") as f:
            targets = [l.strip() for l in f if l.strip()]
            
        if not targets:
            return []
            
        chunk_size = 50
        chunks = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]
        all_results = []
        seen = set() # For deduplication
        
        for i, chunk in enumerate(chunks):
            logger.info("pipeline.nuclei_chunk", chunk=i+1, total=len(chunks), size=len(chunk))
            
            chunk_file = self.output_dir / f"chunk_{i}.txt"
            with open(chunk_file, "w") as f:
                f.write("\n".join(chunk))
                
            chunk_out = self.output_dir / f"nuclei_chunk_{i}.json"
            
            # Exclude intrusive/dos templates, filter only high/critical/medium/low severity.
            cmd = [
                self.nuclei_bin,
                "-l", str(chunk_file),
                "-json-export", str(chunk_out),
                "-silent",
                "-nc",
                "-tlsi",
                "-ni",
                "-c", "50",
                "-etags", "intrusive,dos,fuzz,fuzzing", # Exclude dangerous
                "-s", "low,medium,high,critical", # Pre-filter severity
                "-retries", "1"
            ]
            
            try:
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                # Per-chunk timeout (e.g., 5 mins)
                await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                logger.warning("pipeline.nuclei_timeout", chunk=i+1)
                proc.kill()
            except Exception as e:
                logger.error("pipeline.nuclei_error", chunk=i+1, error=str(e))
                
            if chunk_out.exists():
                with open(chunk_out, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                # Deduplicate by (template_id, url)
                                dedup_key = (finding.get("template-id"), finding.get("matched-at", finding.get("host")))
                                if dedup_key not in seen:
                                    seen.add(dedup_key)
                                    all_results.append(finding)
                            except Exception:
                                pass
                try:
                    chunk_out.unlink() # Cleanup chunk
                except FileNotFoundError:
                    pass
            try:
                chunk_file.unlink() # Cleanup chunk
            except FileNotFoundError:
                pass
            
        # Optional: Save aggregated output
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)
            
        return all_results
