"""
robots.txt parser and respecter.
Fetches and caches robots.txt rules per domain.
"""

from __future__ import annotations

from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import aiohttp
import structlog

logger = structlog.get_logger()


class RobotsChecker:
    """Async robots.txt parser with per-domain caching."""

    def __init__(self, user_agent: str = "*"):
        self.user_agent = user_agent
        self._parsers: dict[str, RobotFileParser] = {}
        self._crawl_delays: dict[str, float] = {}
        self._fetched: set[str] = set()

    def _get_domain(self, url: str) -> str:
        return urlparse(url).netloc.lower()

    async def fetch(self, base_url: str, session: aiohttp.ClientSession | None = None) -> None:
        """Fetch and parse robots.txt for a base URL."""
        domain = self._get_domain(base_url)
        if domain in self._fetched:
            return

        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        parser = RobotFileParser()

        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True

        try:
            async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    parser.parse(text.splitlines())
                    for line in text.splitlines():
                        ll = line.strip().lower()
                        if ll.startswith("crawl-delay:"):
                            try:
                                self._crawl_delays[domain] = float(ll.split(":")[1].strip())
                            except (ValueError, IndexError):
                                pass
                else:
                    parser.allow_all = True
        except Exception as e:
            parser.allow_all = True
            logger.warning("robots.txt fetch failed", domain=domain, error=str(e))
        finally:
            if close_session:
                await session.close()

        self._parsers[domain] = parser
        self._fetched.add(domain)

    def is_allowed(self, url: str) -> bool:
        domain = self._get_domain(url)
        parser = self._parsers.get(domain)
        if parser is None:
            return True
        try:
            return parser.can_fetch(self.user_agent, url)
        except Exception:
            return True

    def get_crawl_delay(self, url: str) -> float:
        return self._crawl_delays.get(self._get_domain(url), 0.0)
