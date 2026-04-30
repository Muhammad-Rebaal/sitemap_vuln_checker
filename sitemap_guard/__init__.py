"""
SiteMap Guard v2 — Ultra-Fast Website Sitemap Crawler & Vulnerability Scanner

A production-grade, open-source tool optimized for maximum speed using:
- Numba JIT for CPU-bound batch computations
- selectolax (C Lexbor) for 30x faster HTML parsing
- aiohttp + winloop for raw async throughput
- rbloom (Rust) for O(1) URL deduplication
- orjson for 10x faster JSON serialization
"""

__version__ = "2.0.0"
__author__ = "SiteMap Guard Contributors"
