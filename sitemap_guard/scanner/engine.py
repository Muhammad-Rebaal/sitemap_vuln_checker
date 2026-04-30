"""
Scanner engine — orchestrates all analyzers and uses Numba for batch aggregation.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable, Optional, Any

import aiohttp
import numpy as np
import structlog

from sitemap_guard.config import Settings
from sitemap_guard.crawler.engine import CrawlerEngine
from sitemap_guard.models import CrawledURL, ScanFinding, Severity, URLScanResult
# from sitemap_guard.scanner.base import BaseAnalyzer
# from sitemap_guard.scanner.analyzers.ssl_analyzer import SSLAnalyzer
# from sitemap_guard.scanner.analyzers.headers_analyzer import HeadersAnalyzer
# from sitemap_guard.scanner.analyzers.content_analyzer import ContentAnalyzer
# from sitemap_guard.scanner.analyzers.dns_analyzer import DNSAnalyzer
# from sitemap_guard.scanner.analyzers.tech_detector import TechDetector
# from sitemap_guard.scanner.analyzers.safebrowsing import SafeBrowsingAnalyzer
# from sitemap_guard.scanner.analyzers.virustotal import VirusTotalAnalyzer
# from sitemap_guard.scanner.analyzers.phishtank import PhishTankAnalyzer

# Note: The above analyzers are currently missing and causing ImportErrors.
# They are being deprecated in favor of the v3 BugBountyPipeline.

from sitemap_guard.utils.scoring import (
    batch_compute_risk_scores,
    compute_site_risk,
    prepare_batch_scoring_data,
)

logger = structlog.get_logger()


class ScannerEngine:
    """
    Scanner orchestrator — runs all enabled analyzers against discovered URLs
    and uses Numba for batch risk score computation.
    """

    def __init__(self, settings: Settings, crawler: CrawlerEngine):
        self.settings = settings
        self.crawler = crawler
        self.analyzers: list = [] # list[BaseAnalyzer]
        self.results: list[URLScanResult] = []
        self._progress_cb: Optional[Callable] = None
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_requests)

    def on_progress(self, callback: Callable) -> None:
        self._progress_cb = callback

    def _register_analyzers(self) -> None:
        """Register enabled analyzers based on settings."""
        enabled = self.settings.get_enabled_analyzers()

        analyzer_map: dict[str, Any] = {
            # "ssl": SSLAnalyzer(),
            # "headers": HeadersAnalyzer(),
            # "content": ContentAnalyzer(),
            # "dns": DNSAnalyzer(),
            # "tech": TechDetector(),
            # "safebrowsing": SafeBrowsingAnalyzer(api_key=self.settings.google_safebrowsing_api_key or ""),
            # "virustotal": VirusTotalAnalyzer(api_key=self.settings.virustotal_api_key or ""),
            # "phishtank": PhishTankAnalyzer(),
        }

        for name in enabled:
            if name in analyzer_map:
                self.analyzers.append(analyzer_map[name])

        logger.info("scanner.analyzers_registered",
                     count=len(self.analyzers),
                     names=[a.name for a in self.analyzers])

    async def scan(self) -> list[URLScanResult]:
        """Run all analyzers against all crawled URLs."""
        self._register_analyzers()

        # Setup analyzers
        for analyzer in self.analyzers:
            await analyzer.setup()

        crawled_urls = self.crawler.discovered_urls
        logger.info("scanner.start", url_count=len(crawled_urls))

        # Batch check with Safe Browsing if available
        sb_analyzer = next((a for a in self.analyzers if isinstance(a, SafeBrowsingAnalyzer)), None)
        if sb_analyzer and sb_analyzer.api_key:
            urls_to_check = [c.url for c in crawled_urls if c.status_code and 200 <= c.status_code < 400]
            await sb_analyzer.batch_check(urls_to_check)

        # Scan all URLs concurrently
        tasks = [self._scan_url(crawled) for crawled in crawled_urls]
        self.results = await asyncio.gather(*tasks)

        # ── Numba batch risk scoring ─────────────────────────────
        if self.results:
            severity_matrix, finding_counts = prepare_batch_scoring_data(self.results)
            if severity_matrix.size > 0:
                scores = batch_compute_risk_scores(severity_matrix, finding_counts)
                for i, result in enumerate(self.results):
                    result.risk_score = round(float(scores[i]), 1)

        # Teardown analyzers
        for analyzer in self.analyzers:
            await analyzer.teardown()

        logger.info("scanner.complete",
                     total_scanned=len(self.results),
                     total_findings=sum(len(r.findings) for r in self.results))

        return self.results

    async def _scan_url(self, crawled: CrawledURL) -> URLScanResult:
        """Run all analyzers against a single URL."""
        async with self._semaphore:
            start = time.monotonic()
            result = URLScanResult(url=crawled.url)

            # Get HTML content and headers from crawler cache
            extracted = self.crawler.extracted_pages.get(crawled.url)
            html_content = None
            headers: dict[str, str] = {}

            # Re-fetch headers if we need them (lightweight HEAD-like data)
            if crawled.status_code and 200 <= crawled.status_code < 400:
                try:
                    connector = aiohttp.TCPConnector(limit=10)
                    async with aiohttp.ClientSession(connector=connector) as session:
                        async with session.get(
                            crawled.url,
                            timeout=aiohttp.ClientTimeout(total=self.settings.request_timeout),
                            headers={"User-Agent": self.settings.user_agent},
                            ssl=False,
                            allow_redirects=True,
                        ) as resp:
                            headers = {k.lower(): v for k, v in resp.headers.items()}
                            if "text/html" in resp.headers.get("content-type", ""):
                                body = await resp.read()
                                html_content = body.decode("utf-8", errors="replace")
                except Exception as e:
                    logger.debug("scanner.fetch_error", url=crawled.url, error=str(e))

            # Run all analyzers concurrently for this URL
            analyzer_tasks = []
            for analyzer in self.analyzers:
                analyzer_tasks.append(
                    analyzer.analyze(
                        url=crawled.url,
                        response_headers=headers,
                        html_content=html_content,
                        status_code=crawled.status_code,
                    )
                )

            analyzer_results = await asyncio.gather(*analyzer_tasks, return_exceptions=True)

            for i, ar in enumerate(analyzer_results):
                analyzer_name = self.analyzers[i].name
                result.analyzers_run.append(analyzer_name)
                if isinstance(ar, Exception):
                    logger.warning("scanner.analyzer_error", analyzer=analyzer_name, error=str(ar))
                elif isinstance(ar, list):
                    result.findings.extend(ar)

            result.scan_duration_ms = round((time.monotonic() - start) * 1000, 2)

            if self._progress_cb:
                self._progress_cb(crawled.url, len(result.findings))

            return result
