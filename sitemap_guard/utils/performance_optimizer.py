from typing import List
from typing import Optional
from typing import Any
"""
Performance optimizer with caching, connection pooling, and async improvements
"""
import asyncio
import aiohttp
import time
from typing import Dict, Any, List, Optional, Callable
from functools import wraps
import hashlib
import json
import pickle
from pathlib import Path
import structlog
from concurrent.futures import ThreadPoolExecutor
import threading
import weakref

logger = structlog.get_logger()

class AsyncCache:
 """High-performance async cache with TTL support"""
 
 def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
 self._cache: Dict[str, Dict[str, Any]] = {}
 self._access_times: Dict[str, float] = {}
 self._max_size = max_size
 self._default_ttl = default_ttl
 self._lock = threading.RLock()
 
 def _make_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
 """Generate cache key from function arguments"""
 key_data = f"{func_name}:{str(args)}:{str(sorted(kwargs.items()))}"
 return hashlib.sha256(key_data.encode()).hexdigest()[:16]
 
 def _cleanup_expired(self):
 """Remove expired cache entries"""
 current_time = time.time()
 with self._lock:
 expired_keys = [
 key for key, data in self._cache.items()
 if current_time > data['expires_at']
 ]
 for key in expired_keys:
 del self._cache[key]
 del self._access_times[key]
 
 def _evict_lru(self):
 """Evict least recently used items if cache is full"""
 with self._lock:
 if len(self._cache) >= self._max_size:
 # Sort by access time and remove oldest 10%
 sorted_keys = sorted(self._access_times.items(), key=lambda x: x[1])
 num_to_remove = max(1, len(sorted_keys) // 10)
 
 for key, _ in sorted_keys[:num_to_remove]:
 if key in self._cache:
 del self._cache[key]
 if key in self._access_times:
 del self._access_times[key]
 
 async def get(self, key: str) -> Optional[Any]:
 """Get cached value"""
 current_time = time.time()
 
 with self._lock:
 if key in self._cache:
 data = self._cache[key]
 if current_time <= data['expires_at']:
 self._access_times[key] = current_time
 return data['value']
 else:
 # Expired
 del self._cache[key]
 del self._access_times[key]
 
 return None
 
 async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
 """Set cached value"""
 if ttl is None:
 ttl = self._default_ttl
 
 current_time = time.time()
 expires_at = current_time + ttl
 
 self._evict_lru()
 
 with self._lock:
 self._cache[key] = {
 'value': value,
 'expires_at': expires_at,
 'created_at': current_time
 }
 self._access_times[key] = current_time
 
 # Periodic cleanup
 if len(self._cache) % 100 == 0:
 self._cleanup_expired()

# Global cache instance
_cache = AsyncCache(max_size=5000, default_ttl=1800) # 30 minutes default

def async_cached(ttl: int = 1800):
 """Decorator for caching async function results"""
 def decorator(func: Callable) -> Callable:
 @wraps(func)
 async def wrapper(*args, **kwargs):
 # Generate cache key
 cache_key = _cache._make_key(func.__name__, args, kwargs)
 
 # Try to get from cache
 cached_result = await _cache.get(cache_key)
 if cached_result is not None:
 logger.debug("cache.hit", func=func.__name__, key=cache_key[:8])
 return cached_result
 
 # Execute function and cache result
 logger.debug("cache.miss", func=func.__name__, key=cache_key[:8])
 result = await func(*args, **kwargs)
 await _cache.set(cache_key, result, ttl)
 
 return result
 return wrapper
 return decorator

class ConnectionPool:
 """Optimized HTTP connection pool manager"""
 
 def __init__(self):
 self._sessions: Dict[str, aiohttp.ClientSession] = {}
 self._lock = asyncio.Lock()
 self._cleanup_task: Optional[asyncio.Task] = None
 
 # Optimal connector settings
 self._connector_config = {
 'limit': 100, # Total connection pool size
 'limit_per_host': 20, # Connections per host
 'ttl_dns_cache': 300, # DNS cache TTL
 'use_dns_cache': True,
 'keepalive_timeout': 30,
 'enable_cleanup_closed': True,
 }
 
 # SSL context for performance
 import ssl
 self._ssl_context = ssl.create_default_context()
 self._ssl_context.check_hostname = False
 self._ssl_context.verify_mode = ssl.CERT_NONE
 
 # Start cleanup task
 self._start_cleanup_task()
 
 def _start_cleanup_task(self):
 """Start periodic cleanup of unused sessions"""
 async def cleanup():
 while True:
 await asyncio.sleep(300) # Cleanup every 5 minutes
 await self._cleanup_sessions()
 
 self._cleanup_task = asyncio.create_task(cleanup())
 
 async def _cleanup_sessions(self):
 """Close unused sessions"""
 async with self._lock:
 # Simple cleanup - could be enhanced with usage tracking
 sessions_to_remove = []
 for key, session in self._sessions.items():
 if session.closed:
 sessions_to_remove.append(key)
 
 for key in sessions_to_remove:
 del self._sessions[key]
 
 async def get_session(self, 
 headers: Optional[Dict[str, str]] = None,
 timeout: int = 30) -> aiohttp.ClientSession:
 """Get or create optimized HTTP session"""
 
 # Create session key based on headers and timeout
 session_key = f"{hash(str(sorted((headers or {}).items())))}_{timeout}"
 
 async with self._lock:
 if session_key not in self._sessions or self._sessions[session_key].closed:
 # Create new optimized session
 connector = aiohttp.TCPConnector(
 ssl=self._ssl_context,
 **self._connector_config
 )
 
 timeout_config = aiohttp.ClientTimeout(total=timeout)
 
 session = aiohttp.ClientSession(
 headers=headers or {},
 connector=connector,
 timeout=timeout_config,
 raise_for_status=False,
 skip_auto_headers=['User-Agent'] # We'll set our own
 )
 
 self._sessions[session_key] = session
 logger.debug("session.created", key=session_key)
 
 return self._sessions[session_key]
 
 async def close_all(self):
 """Close all sessions and cleanup"""
 if self._cleanup_task:
 self._cleanup_task.cancel()
 
 async with self._lock:
 for session in self._sessions.values():
 if not session.closed:
 await session.close()
 self._sessions.clear()

# Global connection pool
_connection_pool = ConnectionPool()

class BatchProcessor:
 """Efficient batch processing for URLs and requests"""
 
 def __init__(self, batch_size: int = 50, max_concurrent: int = 20):
 self.batch_size = batch_size
 self.max_concurrent = max_concurrent
 self._semaphore = asyncio.Semaphore(max_concurrent)
 
 async def process_urls(self, 
 urls: List[str], 
 processor_func: Callable,
 *args, **kwargs) -> List[Any]:
 """Process URLs in optimized batches"""
 
 async def process_with_semaphore(url):
 async with self._semaphore:
 return await processor_func(url, *args, **kwargs)
 
 # Create batches
 batches = [urls[i:i + self.batch_size] 
 for i in range(0, len(urls), self.batch_size)]
 
 all_results = []
 
 for i, batch in enumerate(batches):
 logger.debug("batch.processing", 
 batch_num=i+1, 
 total_batches=len(batches), 
 batch_size=len(batch))
 
 # Process batch concurrently
 batch_tasks = [process_with_semaphore(url) for url in batch]
 batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
 
 # Filter out exceptions
 valid_results = [r for r in batch_results if not isinstance(r, Exception)]
 all_results.extend(valid_results)
 
 # Small delay between batches to be respectful
 if i < len(batches) - 1:
 await asyncio.sleep(0.1)
 
 return all_results

class PerformanceMonitor:
 """Monitor and log performance metrics"""
 
 def __init__(self):
 self._metrics: Dict[str, List[float]] = {}
 self._lock = threading.RLock()
 
 def record_timing(self, operation: str, duration: float):
 """Record operation timing"""
 with self._lock:
 if operation not in self._metrics:
 self._metrics[operation] = []
 
 self._metrics[operation].append(duration)
 
 # Keep only recent measurements
 if len(self._metrics[operation]) > 1000:
 self._metrics[operation] = self._metrics[operation][-500:]
 
 def get_stats(self, operation: str) -> Dict[str, float]:
 """Get performance statistics for operation"""
 with self._lock:
 timings = self._metrics.get(operation, [])
 if not timings:
 return {}
 
 return {
 'count': len(timings),
 'avg': sum(timings) / len(timings),
 'min': min(timings),
 'max': max(timings),
 'recent_avg': sum(timings[-10:]) / min(len(timings), 10)
 }
 
 def log_stats(self):
 """Log all performance statistics"""
 with self._lock:
 for operation, timings in self._metrics.items():
 stats = self.get_stats(operation)
 logger.info("performance.stats", 
 operation=operation, 
 **stats)

# Global performance monitor
_perf_monitor = PerformanceMonitor()

def timed(operation_name: Optional[str] = None):
 """Decorator to measure function execution time"""
 def decorator(func: Callable) -> Callable:
 op_name = operation_name or func.__name__
 
 @wraps(func)
 async def async_wrapper(*args, **kwargs):
 start_time = time.time()
 try:
 result = await func(*args, **kwargs)
 return result
 finally:
 duration = time.time() - start_time
 _perf_monitor.record_timing(op_name, duration)
 
 @wraps(func)
 def sync_wrapper(*args, **kwargs):
 start_time = time.time()
 try:
 result = func(*args, **kwargs)
 return result
 finally:
 duration = time.time() - start_time
 _perf_monitor.record_timing(op_name, duration)
 
 return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
 return decorator

class SmartRetry:
 """Intelligent retry mechanism with exponential backoff"""
 
 def __init__(self, 
 max_attempts: int = 3,
 base_delay: float = 1.0,
 max_delay: float = 60.0,
 exponential_base: float = 2.0):
 self.max_attempts = max_attempts
 self.base_delay = base_delay
 self.max_delay = max_delay
 self.exponential_base = exponential_base
 
 async def execute(self, 
 coro_func: Callable, 
 *args,
 retryable_exceptions: tuple = (Exception,),
 **kwargs) -> Any:
 """Execute function with smart retry logic"""
 
 last_exception = None
 
 for attempt in range(self.max_attempts):
 try:
 return await coro_func(*args, **kwargs)
 
 except retryable_exceptions as e:
 last_exception = e
 
 if attempt == self.max_attempts - 1:
 # Last attempt failed
 break
 
 # Calculate delay with exponential backoff
 delay = min(
 self.base_delay * (self.exponential_base ** attempt),
 self.max_delay
 )
 
 logger.debug("retry.attempt", 
 attempt=attempt + 1,
 max_attempts=self.max_attempts,
 delay=delay,
 error=str(e))
 
 await asyncio.sleep(delay)
 
 # All attempts failed
 raise last_exception

# Utility functions for optimized operations

async def optimized_http_get(url: str, 
 headers: Optional[Dict[str, str]] = None,
 timeout: int = 10) -> Optional[aiohttp.ClientResponse]:
 """Optimized HTTP GET with connection pooling and caching"""
 session = await _connection_pool.get_session(headers, timeout)
 
 retry_handler = SmartRetry(max_attempts=2, base_delay=0.5)
 
 try:
 response = await retry_handler.execute(
 session.get,
 url,
 retryable_exceptions=(aiohttp.ClientError, asyncio.TimeoutError)
 )
 return response
 except Exception as e:
 logger.debug("http_get.failed", url=url, error=str(e))
 return None

@async_cached(ttl=3600)
async def cached_dns_lookup(domain: str) -> List[str]:
 """Cached DNS lookup to avoid repeated queries"""
 try:
 import socket
 loop = asyncio.get_event_loop()
 result = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
 return result[2] # IP addresses
 except Exception:
 return []

def optimize_async_loops():
 """Set optimal asyncio event loop policies"""
 if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
 # Use selector event loop on Windows for better performance
 asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
 
 # Set optimal loop parameters
 loop = asyncio.get_event_loop()
 if hasattr(loop, 'set_debug'):
 loop.set_debug(False) # Disable debug mode for performance

async def cleanup_resources():
 """Cleanup all resources"""
 await _connection_pool.close_all()
 _perf_monitor.log_stats()

# Context manager for resource management
class PerformanceContext:
 """Context manager for performance-optimized operations"""
 
 def __init__(self):
 self.start_time = None
 
 async def __aenter__(self):
 self.start_time = time.time()
 optimize_async_loops()
 return self
 
 async def __aexit__(self, exc_type, exc_val, exc_tb):
 duration = time.time() - self.start_time
 logger.info("operation.completed", duration=duration)
 
 # Log performance stats periodically
 if hasattr(_perf_monitor, '_last_log_time'):
 if time.time() - _perf_monitor._last_log_time > 300: # Every 5 minutes
 _perf_monitor.log_stats()
 _perf_monitor._last_log_time = time.time()
 else:
 _perf_monitor._last_log_time = time.time()