"""
High-performance async BFS web crawler using aiohttp.

Uses aiohttp with TCPConnector for connection pooling,
rbloom for O(1) URL deduplication, and selectolax for parsing.
"""

from __future__ import annotations

import os
import asyncio
import time
from collections import deque
from typing import Callable, Optional
from urllib.parse import urlparse

import aiohttp
import structlog

from sitemap_guard.config import Settings
from sitemap_guard.crawler.link_extractor import ExtractedPage, extract_links
from sitemap_guard.crawler.robots import RobotsChecker
from sitemap_guard.models import CrawledURL
from sitemap_guard.utils.bloom import BloomFilter
from sitemap_guard.utils.url_utils import (
    extract_domain,
    is_same_domain,
    is_valid_http_url,
    normalize_url,
    should_skip_url,
)

logger = structlog.get_logger()


class CrawlerEngine:
    """
    Ultra-fast async BFS web crawler.

    Features:
    - aiohttp with TCPConnector (connection pooling, keepalive)
    - rbloom Bloom filter for O(1) URL dedup (handles millions)
    - selectolax for 30x faster HTML parsing
    - Configurable concurrency via asyncio.Semaphore
    - robots.txt compliance
    - Domain scope enforcement
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_domain = extract_domain(settings.target_url)
        self.bloom = BloomFilter(
            capacity=settings.bloom_filter_capacity,
            error_rate=settings.bloom_filter_error_rate,
        )
        self.discovered_urls: list[CrawledURL] = []
        self.extracted_pages: dict[str, ExtractedPage] = {}
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
        self._robots = RobotsChecker(user_agent=settings.user_agent)
        self._progress_cb: Optional[Callable] = None
        self._crawl_delay: float = 0.0
        self._total_requests = 0
        self._failed_requests = 0

    def on_progress(self, callback: Callable) -> None:
        """Register callback: callback(crawled_count, queue_size, current_url)."""
        self._progress_cb = callback

    async def crawl(self) -> list[CrawledURL]:
        """Crawl target website. Returns list of all discovered URLs."""
        target = self.settings.target_url
        logger.info("crawl.start", target=target, max_depth=self.settings.max_crawl_depth,
                     concurrency=self.settings.max_concurrent_requests)

        connector = aiohttp.TCPConnector(
            limit=self.settings.max_concurrent_requests,
            limit_per_host=self.settings.max_concurrent_requests,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.settings.request_timeout)
        headers = {"User-Agent": self.settings.user_agent}

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers,
        ) as session:
            # Fetch robots.txt
            if self.settings.respect_robots_txt:
                await self._robots.fetch(target, session)
                self._crawl_delay = self._robots.get_crawl_delay(target)

            # BFS
            queue: deque[tuple[str, int, Optional[str]]] = deque()
            start_url = normalize_url(target)
            queue.append((start_url, 0, None))
            self.bloom.add(start_url)

            while queue:
                # Take batch from queue
                batch_size = min(len(queue), self.settings.max_concurrent_requests)
                batch = [queue.popleft() for _ in range(batch_size)]

                # Process concurrently
                tasks = [
                    self._crawl_url(session, url, depth, parent)
                    for url, depth, parent in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Exception):
                        logger.warning("crawl.task_error", error=str(result))
                        continue
                    if result is None:
                        continue

                    crawled_url, new_links = result

                    if crawled_url.depth < self.settings.max_crawl_depth:
                        for link in new_links:
                            normalized = normalize_url(link)
                            if self.bloom.add_if_absent(normalized):
                                if (is_valid_http_url(normalized)
                                        and not should_skip_url(normalized)
                                        and is_same_domain(normalized, self.base_domain,
                                                           self.settings.follow_subdomains)):
                                    if (not self.settings.respect_robots_txt
                                            or self._robots.is_allowed(normalized)):
                                        queue.append((normalized, crawled_url.depth + 1,
                                                       crawled_url.url))

        logger.info("crawl.complete", total=len(self.discovered_urls),
                     requests=self._total_requests, failed=self._failed_requests)
        return self.discovered_urls

    async def _crawl_url(
        self, session: aiohttp.ClientSession, url: str, depth: int, parent: Optional[str],
    ) -> Optional[tuple[CrawledURL, list[str]]]:
        """Crawl a single URL."""
        async with self._semaphore:
            if self._crawl_delay > 0:
                await asyncio.sleep(self._crawl_delay)

            self._total_requests += 1
            start = time.monotonic()

            try:
                body = b""
                content_type = ""
                final_url = url
                resp_status = 0
                elapsed_ms = 0.0

                if self.settings.use_obscura:
                    # Execute Obscura fetch
                    obscura_cmd = [
                        self.settings.obscura_path,
                        "fetch", url,
                        "--dump", "html",
                        "--stealth",
                        "--quiet"
                    ]
                    
                    if os.path.exists(self.settings.obscura_path):
                        process = await asyncio.create_subprocess_exec(
                            *obscura_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        try:
                            stdout, stderr = await asyncio.wait_for(
                                process.communicate(), 
                                timeout=self.settings.request_timeout
                            )
                            elapsed_ms = (time.monotonic() - start) * 1000
                            
                            if process.returncode == 0:
                                body = stdout
                                resp_status = 200
                                content_type = "text/html"
                            else:
                                logger.error("crawler.obscura_error", url=url, error=stderr.decode("utf-8").strip())
                        except asyncio.TimeoutError:
                            process.kill()
                            logger.warning("crawler.obscura_timeout", url=url)

                # Fallback to aiohttp if Obscura is disabled or failed
                if resp_status == 0:
                    start_aio = time.monotonic()
                    async with session.get(url, allow_redirects=True, ssl=False) as resp:
                        elapsed_ms = (time.monotonic() - start_aio) * 1000
                        content_type = resp.headers.get("content-type", "")
                        final_url = str(resp.url)
                        resp_status = resp.status

                        if "text/html" in content_type and resp.status == 200:
                            body = await resp.read()

                crawled = CrawledURL(
                    url=final_url,
                    status_code=resp_status,
                    content_type=content_type,
                    response_time_ms=round(elapsed_ms, 2),
                    depth=depth,
                    parent_url=parent,
                    content_length=len(body),
                    redirect_url=final_url if final_url != url else None,
                )

                new_links: list[str] = []
                if body and "text/html" in content_type:
                    try:
                        html_text = body.decode("utf-8", errors="replace")
                        extracted = extract_links(html_text, final_url)
                        crawled.title = extracted.title
                        crawled.meta_description = extracted.meta_description
                        new_links = extracted.links
                        self.extracted_pages[final_url] = extracted
                    except Exception as e:
                        logger.warning("crawler.parse_error", url=url, error=str(e))

                self.discovered_urls.append(crawled)
                if self._progress_cb:
                    self._progress_cb(len(self.discovered_urls), 0, url)

                return crawled, new_links

            except asyncio.TimeoutError:
                self._failed_requests += 1
                crawled = CrawledURL(url=url, status_code=0, depth=depth, parent_url=parent,
                                     response_time_ms=(time.monotonic() - start) * 1000)
                self.discovered_urls.append(crawled)
                return crawled, []

            except aiohttp.ClientError as e:
                self._failed_requests += 1
                logger.warning("crawl.http_error", url=url, error=str(e))
                crawled = CrawledURL(url=url, status_code=0, depth=depth, parent_url=parent,
                                     response_time_ms=(time.monotonic() - start) * 1000)
                self.discovered_urls.append(crawled)
                return crawled, []

            except Exception as e:
                self._failed_requests += 1
                logger.error("crawl.unexpected", url=url, error=str(e))
                return None
