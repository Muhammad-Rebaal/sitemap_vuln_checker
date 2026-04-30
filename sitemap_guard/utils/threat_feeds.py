"""
Utility to manage offline threat feeds for URL reputation checking.
Downloads community-maintained feeds and populates a Bloom filter.
"""
import httpx
import asyncio
from pathlib import Path
from typing import List, Set
import structlog
from sitemap_guard.utils.bloom import BloomFilter

logger = structlog.get_logger()

DEFAULT_FEEDS = [
    "https://urlhaus.abuse.ch/downloads/text/",  # Malware URLs
    "https://openphish.com/feed.txt",            # Phishing URLs
]

class ThreatFeedManager:
    """
    Manages local threat feeds and provides fast lookups via Bloom filter.
    """
    def __init__(self, cache_dir: Path, capacity: int = 1_000_000):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.bloom = BloomFilter(capacity=capacity, error_rate=0.0001)
        self.is_loaded = False

    async def load_feeds(self, urls: List[str] = DEFAULT_FEEDS, force_update: bool = False):
        """
        Load feeds into memory. Downloads them if not present or force_update is True.
        """
        logger.info("threat_feeds.loading", count=len(urls))
        
        tasks = [self._get_feed(url, force_update) for url in urls]
        feeds_content = await asyncio.gather(*tasks)
        
        total_items = 0
        for content in feeds_content:
            if not content:
                continue
            
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self.bloom.add(line)
                total_items += 1
        
        self.is_loaded = True
        logger.info("threat_feeds.loaded", total_items=total_items, bloom_count=self.bloom.count)

    async def _get_feed(self, url: str, force_update: bool) -> str:
        """Fetch feed from local cache or remote URL, with 6h TTL and gzip cache."""
        import hashlib
        import gzip
        import time
        
        url_hash = hashlib.md5(url.encode()).hexdigest()
        cache_file = self.cache_dir / f"feed_{url_hash}.txt.gz"
        
        # 6 hours TTL (6 * 60 * 60 = 21600 seconds)
        ttl = 21600
        
        needs_update = force_update
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age > ttl:
                logger.info("threat_feeds.cache_expired", url=url, age_hours=age/3600)
                needs_update = True
        else:
            needs_update = True
            
        if not needs_update:
            logger.debug("threat_feeds.using_cache", url=url)
            try:
                with gzip.open(cache_file, "rt", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                logger.error("threat_feeds.cache_read_error", error=str(e))
                needs_update = True
                
        try:
            logger.info("threat_feeds.downloading", url=url)
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                content = resp.text
                with gzip.open(cache_file, "wt", encoding="utf-8") as f:
                    f.write(content)
                return content
        except Exception as e:
            logger.error("threat_feeds.download_failed", url=url, error=str(e))
            if cache_file.exists():
                try:
                    with gzip.open(cache_file, "rt", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    pass
            return ""

    def is_malicious(self, url: str) -> bool:
        """Check if a URL is in the threat bloom filter."""
        if not self.is_loaded:
            return False
        return url in self.bloom
