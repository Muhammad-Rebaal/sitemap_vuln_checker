"""
High-performance URL deduplication using Bloom filters.

Primary: rbloom (Rust-based, ultra-fast)
Fallback: Numba-accelerated MurmurHash3 with NumPy bit array

Handles millions of URLs with O(1) lookups and minimal memory.
"""

from __future__ import annotations

import hashlib
from typing import Optional

import numpy as np
import structlog

logger = structlog.get_logger()

# Try to import rbloom (Rust-based, preferred)
try:
    from rbloom import Bloom as RustBloom

    HAS_RBLOOM = True
except ImportError:
    HAS_RBLOOM = False
    logger.warning("rbloom not available, using Python fallback Bloom filter")

# Try Numba for fallback hash acceleration
try:
    from numba import njit

    HAS_NUMBA = True
except ImportError:
    HAS_NUMBA = False


# ── Numba-accelerated MurmurHash3 (fallback) ────────────────────────

if HAS_NUMBA:

    @njit(cache=True)
    def _murmurhash3_32(data: np.ndarray, seed: int) -> int:
        """
        Numba JIT MurmurHash3 32-bit implementation.
        ~20x faster than Python hash for Bloom filter hashing.
        """
        length = data.shape[0]
        h = np.uint32(seed)
        c1 = np.uint32(0xCC9E2D51)
        c2 = np.uint32(0x1B873593)

        # Body
        n_blocks = length // 4
        for i in range(n_blocks):
            idx = i * 4
            k = np.uint32(data[idx]) | (np.uint32(data[idx + 1]) << 8) | \
                (np.uint32(data[idx + 2]) << 16) | (np.uint32(data[idx + 3]) << 24)

            k = np.uint32(k * c1)
            k = np.uint32((k << 15) | (k >> 17))
            k = np.uint32(k * c2)

            h = np.uint32(h ^ k)
            h = np.uint32((h << 13) | (h >> 19))
            h = np.uint32(h * np.uint32(5) + np.uint32(0xE6546B64))

        # Tail
        tail_idx = n_blocks * 4
        k1 = np.uint32(0)
        tail_size = length & 3

        if tail_size >= 3:
            k1 = np.uint32(k1 ^ (np.uint32(data[tail_idx + 2]) << 16))
        if tail_size >= 2:
            k1 = np.uint32(k1 ^ (np.uint32(data[tail_idx + 1]) << 8))
        if tail_size >= 1:
            k1 = np.uint32(k1 ^ np.uint32(data[tail_idx]))
            k1 = np.uint32(k1 * c1)
            k1 = np.uint32((k1 << 15) | (k1 >> 17))
            k1 = np.uint32(k1 * c2)
            h = np.uint32(h ^ k1)

        # Finalize
        h = np.uint32(h ^ np.uint32(length))
        h = np.uint32(h ^ (h >> 16))
        h = np.uint32(h * np.uint32(0x85EBCA6B))
        h = np.uint32(h ^ (h >> 13))
        h = np.uint32(h * np.uint32(0xC2B2AE35))
        h = np.uint32(h ^ (h >> 16))

        return int(h)


class BloomFilter:
    """
    High-performance Bloom filter for URL deduplication.

    Automatically uses rbloom (Rust) if available, falls back to
    Numba-accelerated Python implementation.
    """

    def __init__(
        self,
        capacity: int = 1_000_000,
        error_rate: float = 0.001,
    ):
        self.capacity = capacity
        self.error_rate = error_rate
        self._count = 0

        if HAS_RBLOOM:
            self._impl = "rbloom"
            self._bloom = RustBloom(capacity, error_rate)
            logger.debug("using rbloom (Rust) Bloom filter", capacity=capacity)
        else:
            self._impl = "python"
            # Calculate optimal size and hash count
            import math

            self._size = int(-capacity * math.log(error_rate) / (math.log(2) ** 2))
            self._hash_count = int((self._size / capacity) * math.log(2))
            self._bit_array = np.zeros(self._size, dtype=np.uint8)
            logger.debug(
                "using Python fallback Bloom filter",
                capacity=capacity,
                bit_size=self._size,
                hash_count=self._hash_count,
            )

    def add(self, item: str) -> None:
        """Add an item to the Bloom filter."""
        if HAS_RBLOOM:
            self._bloom.add(item)
        else:
            for idx in self._get_indices(item):
                self._bit_array[idx] = 1
        self._count += 1

    def __contains__(self, item: str) -> bool:
        """Check if an item might be in the Bloom filter (may have false positives)."""
        if HAS_RBLOOM:
            return item in self._bloom
        else:
            return all(self._bit_array[idx] == 1 for idx in self._get_indices(item))

    def add_if_absent(self, item: str) -> bool:
        """
        Add item only if not present. Returns True if item was new.

        This is the primary method for URL deduplication during crawling.
        """
        if item in self:
            return False
        self.add(item)
        return True

    @property
    def count(self) -> int:
        return self._count

    def _get_indices(self, item: str) -> list[int]:
        """Get bit indices for an item using double hashing."""
        item_bytes = item.encode("utf-8")

        if HAS_NUMBA:
            data = np.frombuffer(item_bytes, dtype=np.uint8).copy()
            h1 = _murmurhash3_32(data, 0)
            h2 = _murmurhash3_32(data, h1)
        else:
            h1 = int(hashlib.md5(item_bytes).hexdigest()[:8], 16)
            h2 = int(hashlib.md5(item_bytes + b"\x01").hexdigest()[:8], 16)

        indices = []
        for i in range(self._hash_count):
            idx = (h1 + i * h2) % self._size
            indices.append(idx)
        return indices

    def __len__(self) -> int:
        return self._count

    def __repr__(self) -> str:
        return (
            f"BloomFilter(impl={self._impl}, capacity={self.capacity}, "
            f"count={self._count}, error_rate={self.error_rate})"
        )
