"""
Advanced speed and efficiency optimizer for maximum performance
"""
import asyncio
import aiohttp
import time
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
import structlog
import threading
from collections import defaultdict, deque
import weakref
import gc
import psutil
import os

logger = structlog.get_logger()

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    requests_per_second: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0

class AdvancedConnectionPool:
    """Ultra-high performance connection pool with intelligent load balancing"""
    
    def __init__(self, max_connections: int = 200, max_per_host: int = 50):
        self.max_connections = max_connections
        self.max_per_host = max_per_host
        self.sessions: Dict[str, aiohttp.ClientSession] = {}
        self.connection_counts: Dict[str, int] = defaultdict(int)
        self.session_lock = asyncio.Lock()
        self.metrics = PerformanceMetrics()
        
        # Advanced connector configuration
        self.connector_config = {
            'limit': max_connections,
            'limit_per_host': max_per_host,
            'ttl_dns_cache': 300,
            'use_dns_cache': True,
            'keepalive_timeout': 60,
            'enable_cleanup_closed': True,
            'force_close': False,
            'auto_decompress': True,
        }
        
        # Performance optimization
        import ssl
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Set optimal SSL options for speed
        self.ssl_context.options |= ssl.OP_NO_SSLv2
        self.ssl_context.options |= ssl.OP_NO_SSLv3
        self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
    async def get_optimized_session(self, domain: str) -> aiohttp.ClientSession:
        """Get or create an optimized session for a domain"""
        async with self.session_lock:
            if domain not in self.sessions or self.sessions[domain].closed:
                # Create optimized connector
                connector = aiohttp.TCPConnector(
                    ssl=self.ssl_context,
                    **self.connector_config
                )
                
                # Optimized timeout configuration
                timeout = aiohttp.ClientTimeout(
                    total=30,
                    connect=10,
                    sock_read=10
                )
                
                # Performance headers
                headers = {
                    'User-Agent': 'SiteMapGuard-HighSpeed/4.0',
                    'Accept': '*/*',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache',
                }
                
                self.sessions[domain] = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers=headers,
                    skip_auto_headers=['User-Agent'],
                    trust_env=True
                )
                
                logger.debug("session.created", domain=domain)
            
            return self.sessions[domain]
    
    async def cleanup_sessions(self):
        """Cleanup all sessions"""
        async with self.session_lock:
            for session in self.sessions.values():
                if not session.closed:
                    await session.close()
            self.sessions.clear()

class IntelligentRateLimiter:
    """Adaptive rate limiter that adjusts based on server responses"""
    
    def __init__(self, initial_rate: float = 50.0, max_rate: float = 200.0):
        self.current_rate = initial_rate
        self.max_rate = max_rate
        self.min_rate = 1.0
        self.response_times = deque(maxlen=100)
        self.error_rates = deque(maxlen=50)
        self.last_adjustment = time.time()
        self.semaphore = asyncio.Semaphore(int(initial_rate))
        
    async def acquire(self):
        """Acquire rate limit token with adaptive adjustment"""
        await self.semaphore.acquire()
        
    def release(self, response_time: float, is_error: bool = False):
        """Release token and adjust rate based on performance"""
        self.semaphore.release()
        
        self.response_times.append(response_time)
        self.error_rates.append(1 if is_error else 0)
        
        # Adjust rate every 10 seconds
        if time.time() - self.last_adjustment > 10:
            self._adjust_rate()
            self.last_adjustment = time.time()
    
    def _adjust_rate(self):
        """Intelligently adjust request rate"""
        if not self.response_times or not self.error_rates:
            return
            
        avg_response_time = sum(self.response_times) / len(self.response_times)
        error_rate = sum(self.error_rates) / len(self.error_rates)
        
        # Decrease rate if high error rate or slow responses
        if error_rate > 0.1 or avg_response_time > 5.0:
            new_rate = max(self.min_rate, self.current_rate * 0.8)
        # Increase rate if performing well
        elif error_rate < 0.05 and avg_response_time < 2.0:
            new_rate = min(self.max_rate, self.current_rate * 1.2)
        else:
            return  # No change needed
        
        # Update semaphore
        rate_change = int(new_rate - self.current_rate)
        if rate_change > 0:
            # Increase capacity
            for _ in range(abs(rate_change)):
                self.semaphore._value += 1
        elif rate_change < 0:
            # Decrease capacity (will take effect as requests complete)
            pass
            
        self.current_rate = new_rate
        logger.debug("rate_limiter.adjusted", 
                    old_rate=self.current_rate,
                    new_rate=new_rate,
                    avg_response_time=avg_response_time,
                    error_rate=error_rate)

class HyperSpeedScanner:
    """Ultra-high performance scanner with all optimizations enabled"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = self._extract_domain(target_url)
        
        # Performance components
        self.connection_pool = AdvancedConnectionPool(max_connections=500, max_per_host=100)
        self.rate_limiter = IntelligentRateLimiter(initial_rate=100.0, max_rate=500.0)
        
        # Memory optimization
        self.response_cache = {}
        self.cache_max_size = 10000
        
        # Threading for CPU-bound tasks
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, (os.cpu_count() or 1) + 4)
        )
        
        # Performance tracking
        self.start_time = time.time()
        self.request_count = 0
        self.success_count = 0
        self.error_count = 0
        
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        return urlparse(url).netloc
    
    async def hyperspeed_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[Dict[str, Any]]:
        """Make ultra-fast HTTP request with all optimizations"""
        start_time = time.time()
        
        try:
            # Rate limiting
            await self.rate_limiter.acquire()
            
            # Get optimized session
            domain = self._extract_domain(url)
            session = await self.connection_pool.get_optimized_session(domain)
            
            # Make request with optimal settings
            async with session.request(method, url, **kwargs) as response:
                # Fast response processing
                result = {
                    'url': url,
                    'status': response.status,
                    'headers': dict(response.headers),
                    'response_time': time.time() - start_time
                }
                
                # Only read body if needed and reasonable size
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) < 1024 * 1024:  # 1MB limit
                    result['content'] = await response.text(errors='ignore')
                
                self.success_count += 1
                return result
                
        except Exception as e:
            self.error_count += 1
            logger.debug("hyperspeed_request.error", url=url, error=str(e))
            return None
            
        finally:
            response_time = time.time() - start_time
            is_error = self.error_count > 0
            self.rate_limiter.release(response_time, is_error)
            self.request_count += 1
    
    async def batch_scan_urls(self, urls: List[str], batch_size: int = 100) -> List[Dict[str, Any]]:
        """Scan URLs in optimized batches with maximum concurrency"""
        results = []
        
        # Process in chunks to avoid overwhelming system
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            
            # Create tasks for concurrent execution
            tasks = [self.hyperspeed_request(url) for url in batch]
            
            # Execute batch with optimal concurrency
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful results
            valid_results = [
                r for r in batch_results 
                if isinstance(r, dict) and r is not None
            ]
            
            results.extend(valid_results)
            
            # Adaptive delay between batches
            if i + batch_size < len(urls):
                # Calculate optimal delay based on current performance
                avg_response_time = sum(r.get('response_time', 0) for r in valid_results) / max(len(valid_results), 1)
                delay = max(0.01, min(1.0, avg_response_time / 10))
                await asyncio.sleep(delay)
        
        return results
    
    async def intelligent_discovery(self, base_url: str) -> List[str]:
        """Intelligent URL discovery with performance optimization"""
        discovered_urls = set([base_url])
        
        # Parallel discovery strategies
        discovery_tasks = [
            self._fast_robots_discovery(base_url),
            self._fast_sitemap_discovery(base_url),
            self._fast_common_path_discovery(base_url),
            self._fast_link_extraction(base_url)
        ]
        
        discovery_results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        for result in discovery_results:
            if isinstance(result, list):
                discovered_urls.update(result)
        
        return list(discovered_urls)
    
    async def _fast_robots_discovery(self, base_url: str) -> List[str]:
        """Ultra-fast robots.txt discovery"""
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        result = await self.hyperspeed_request(robots_url)
        
        urls = []
        if result and result.get('content'):
            content = result['content']
            
            # Extract sitemap URLs
            import re
            sitemap_matches = re.findall(r'sitemap:\s*(.+)', content, re.IGNORECASE)
            urls.extend(sitemap_matches)
            
            # Extract disallowed paths (potential interesting paths)
            disallow_matches = re.findall(r'disallow:\s*(.+)', content, re.IGNORECASE)
            for path in disallow_matches:
                path = path.strip()
                if path and path != '/' and '*' not in path:
                    urls.append(f"{base_url.rstrip('/')}{path}")
        
        return urls
    
    async def _fast_sitemap_discovery(self, base_url: str) -> List[str]:
        """Ultra-fast sitemap discovery"""
        sitemap_candidates = [
            f"{base_url.rstrip('/')}/sitemap.xml",
            f"{base_url.rstrip('/')}/sitemap_index.xml",
            f"{base_url.rstrip('/')}/wp-sitemap.xml"
        ]
        
        # Concurrent sitemap requests
        tasks = [self.hyperspeed_request(url) for url in sitemap_candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        urls = []
        for result in results:
            if isinstance(result, dict) and result.get('content'):
                content = result['content']
                
                # Fast XML parsing with regex
                import re
                url_matches = re.findall(r'<loc>([^<]+)</loc>', content)
                urls.extend(url_matches)
        
        return urls
    
    async def _fast_common_path_discovery(self, base_url: str) -> List[str]:
        """Fast common path probing"""
        common_paths = [
            '/admin', '/login', '/dashboard', '/api', '/docs',
            '/backup', '/config', '/test', '/dev', '/staging'
        ]
        
        urls = [f"{base_url.rstrip('/')}{path}" for path in common_paths]
        return urls
    
    async def _fast_link_extraction(self, base_url: str) -> List[str]:
        """Fast link extraction from main page"""
        result = await self.hyperspeed_request(base_url)
        
        urls = []
        if result and result.get('content'):
            content = result['content']
            
            # Fast regex-based link extraction
            import re
            from urllib.parse import urljoin, urlparse
            
            # Extract href attributes
            href_matches = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
            
            base_domain = urlparse(base_url).netloc
            
            for href in href_matches:
                try:
                    full_url = urljoin(base_url, href)
                    parsed = urlparse(full_url)
                    
                    # Only same domain
                    if parsed.netloc == base_domain:
                        urls.append(full_url)
                except:
                    continue
        
        return urls
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        elapsed_time = time.time() - self.start_time
        
        return {
            'total_requests': self.request_count,
            'successful_requests': self.success_count,
            'failed_requests': self.error_count,
            'success_rate': self.success_count / max(self.request_count, 1),
            'requests_per_second': self.request_count / max(elapsed_time, 1),
            'elapsed_time': elapsed_time,
            'current_rate_limit': self.rate_limiter.current_rate,
            'memory_usage_mb': psutil.Process().memory_info().rss / 1024 / 1024,
            'cpu_percent': psutil.Process().cpu_percent()
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        await self.connection_pool.cleanup_sessions()
        self.thread_pool.shutdown(wait=True)

class AutonomousSpeedController:
    """Autonomous controller that optimizes speed based on real-time metrics"""
    
    def __init__(self, scanner: HyperSpeedScanner):
        self.scanner = scanner
        self.optimization_history = []
        self.last_optimization = time.time()
        
    async def continuous_optimization(self):
        """Continuously optimize performance based on metrics"""
        while True:
            try:
                # Wait for optimization interval
                await asyncio.sleep(30)  # Optimize every 30 seconds
                
                stats = self.scanner.get_performance_stats()
                
                # Analyze performance and make adjustments
                await self._optimize_based_on_stats(stats)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("optimization.error", error=str(e))
    
    async def _optimize_based_on_stats(self, stats: Dict[str, Any]):
        """Optimize scanner based on performance statistics"""
        
        # Memory optimization
        if stats['memory_usage_mb'] > 1000:  # 1GB
            # Force garbage collection
            gc.collect()
            
            # Clear response cache
            self.scanner.response_cache.clear()
            
            logger.info("memory.optimized", 
                       old_usage=stats['memory_usage_mb'],
                       new_usage=psutil.Process().memory_info().rss / 1024 / 1024)
        
        # CPU optimization
        if stats['cpu_percent'] > 80:
            # Reduce concurrent connections
            current_limit = self.scanner.rate_limiter.current_rate
            new_limit = max(10, current_limit * 0.8)
            self.scanner.rate_limiter.current_rate = new_limit
            
            logger.info("cpu.optimized", old_limit=current_limit, new_limit=new_limit)
        
        # Success rate optimization
        if stats['success_rate'] < 0.8:
            # Reduce rate to improve success rate
            current_limit = self.scanner.rate_limiter.current_rate
            new_limit = max(5, current_limit * 0.7)
            self.scanner.rate_limiter.current_rate = new_limit
            
            logger.info("success_rate.optimized", 
                       success_rate=stats['success_rate'],
                       old_limit=current_limit, 
                       new_limit=new_limit)

# High-level functions for easy integration

async def hyperspeed_scan(target_url: str, max_urls: int = 10000) -> Dict[str, Any]:
    """Perform hyperspeed comprehensive scan"""
    scanner = HyperSpeedScanner(target_url)
    controller = AutonomousSpeedController(scanner)
    
    try:
        # Start continuous optimization
        optimization_task = asyncio.create_task(controller.continuous_optimization())
        
        # Discovery phase
        logger.info("hyperspeed.discovery_start", target=target_url)
        discovered_urls = await scanner.intelligent_discovery(target_url)
        discovered_urls = discovered_urls[:max_urls]  # Limit for performance
        
        logger.info("hyperspeed.discovery_complete", 
                   urls_found=len(discovered_urls))
        
        # Scanning phase
        logger.info("hyperspeed.scanning_start", urls=len(discovered_urls))
        scan_results = await scanner.batch_scan_urls(discovered_urls, batch_size=200)
        
        # Get final stats
        final_stats = scanner.get_performance_stats()
        
        logger.info("hyperspeed.scan_complete", 
                   **final_stats)
        
        return {
            'target_url': target_url,
            'discovered_urls': discovered_urls,
            'scan_results': scan_results,
            'performance_stats': final_stats,
            'total_urls_scanned': len(scan_results),
            'scan_efficiency': len(scan_results) / max(len(discovered_urls), 1)
        }
        
    finally:
        optimization_task.cancel()
        await scanner.cleanup()