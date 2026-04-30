"""
Async token-bucket rate limiter for API calls.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    """Async rate limiter using sliding-window approach."""

    def __init__(
        self,
        requests_per_second: float = 10.0,
        requests_per_minute: float = 0.0,
        name: str = "default",
    ):
        self.name = name
        self.rps = requests_per_second
        self.rpm = requests_per_minute
        self._min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._last_request_time = 0.0
        self._minute_window: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request is allowed under the rate limit."""
        async with self._lock:
            now = time.monotonic()

            if self._min_interval > 0:
                elapsed = now - self._last_request_time
                if elapsed < self._min_interval:
                    await asyncio.sleep(self._min_interval - elapsed)
                    now = time.monotonic()

            if self.rpm > 0:
                cutoff = now - 60.0
                while self._minute_window and self._minute_window[0] < cutoff:
                    self._minute_window.popleft()

                if len(self._minute_window) >= self.rpm:
                    wait_time = 60.0 - (now - self._minute_window[0])
                    if wait_time > 0:
                        await asyncio.sleep(wait_time)
                        now = time.monotonic()
                        cutoff = now - 60.0
                        while self._minute_window and self._minute_window[0] < cutoff:
                            self._minute_window.popleft()

                self._minute_window.append(now)

            self._last_request_time = now

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *args):
        pass


class MultiRateLimiter:
    """Manages multiple named rate limiters."""

    def __init__(self):
        self._limiters: dict[str, RateLimiter] = {}

    def register(
        self, name: str, requests_per_second: float = 10.0, requests_per_minute: float = 0.0,
    ) -> RateLimiter:
        limiter = RateLimiter(requests_per_second=requests_per_second,
                              requests_per_minute=requests_per_minute, name=name)
        self._limiters[name] = limiter
        return limiter

    def get(self, name: str) -> RateLimiter:
        if name not in self._limiters:
            return self.register(name, requests_per_second=10.0)
        return self._limiters[name]
