"""
Enhanced internal page discovery for PHP, JS, and other file types
with clickable links and comprehensive file type support
"""
import asyncio
import aiohttp
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urljoin, urlparse, quote
import structlog
from dataclasses import dataclass
import time
import mimetypes

logger = structlog.get_logger()

@dataclass
class InternalPage:
    """Represents a discovered internal page"""
    url: str
    file_type: str
    status_code: int
    size_bytes: int
    content_type: str
    last_modified: Optional[str] = None
    is_accessible: bool = False
    content_preview: Optional[str] = None
    security_headers: Dict[str, str] = None
    redirect_url: Optional[str] = None
    response_time_ms: float = 0.0

class ComprehensiveInternalScanner:
    """
    Advanced scanner for discovering internal pages including:
    - PHP files, JS files, CSS files, images
    - Admin panels, configuration files, backup files
    - API endpoints, documentation pages
    - Database files, log files, temporary files
    """
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.discovered_pages: List[InternalPage] = []
        
        # SSL configuration for problematic sites
        import ssl
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Comprehensive file extensions to search for
        self.target_extensions = {
            # Scripts and code
            'php': ['.php', '.php3', '.php4', '.php5', '.phtml', '.inc'],
            'javascript': ['.js', '.jsx', '.ts', '.tsx', '.json'],
            'python': ['.py', '.pyc', '.pyo', '.wsgi'],
            'asp': ['.asp', '.aspx', '.ashx', '.asmx'],
            'jsp': ['.jsp', '.jspx', '.jsf'],
            'perl': ['.pl', '.cgi', '.pm'],
            'ruby': ['.rb', '.rhtml', '.erb'],
            
            # Configuration and data files
            'config': ['.conf', '.config', '.cfg', '.ini', '.yaml', '.yml', '.toml'],
            'data': ['.xml', '.csv', '.sql', '.db', '.sqlite', '.mdb'],
            'backup': ['.bak', '.backup', '.old', '.orig', '.tmp', '.swp', '.swo'],
            'log': ['.log', '.logs', '.trace', '.debug'],
            
            # Web assets
            'stylesheet': ['.css', '.scss', '.sass', '.less'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp'],
            'documents': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt'],
            'archives': ['.zip', '.rar', '.tar', '.gz', '.bz2', '.7z'],
            
            # Special files
            'htaccess': ['.htaccess', '.htpasswd'],
            'git': ['.git', '.gitignore', '.gitconfig'],
            'env': ['.env', '.env.local', '.env.production', '.env.staging']
        }
        
        # Comprehensive path patterns to check
        self.path_patterns = [
            # Admin and management
            'admin', 'administrator', 'administration', 'manage', 'management',
            'control', 'panel', 'dashboard', 'cp', 'backend', 'backoffice',
            
            # CMS specific
            'wp-admin', 'wp-content', 'wp-includes', 'wp-config.php',
            'sites/default/files', 'modules', 'themes', 'plugins',
            'administrator/components', 'administrator/modules',
            
            # API and services
            'api', 'rest', 'graphql', 'soap', 'rpc', 'services',
            'v1', 'v2', 'v3', 'endpoints', 'webhooks',
            
            # Development and testing
            'dev', 'development', 'test', 'testing', 'staging', 'stage',
            'debug', 'beta', 'alpha', 'demo', 'sample', 'example',
            
            # Configuration and setup
            'config', 'configuration', 'settings', 'setup', 'install',
            'installation', 'upgrade', 'update', 'migration',
            
            # Data and databases
            'data', 'database', 'db', 'sql', 'mysql', 'postgres',
            'mongo', 'redis', 'elastic', 'search',
            
            # Files and uploads
            'files', 'uploads', 'upload', 'media', 'assets', 'static',
            'resources', 'content', 'attachments', 'documents',
            
            # Backup and archives
            'backup', 'backups', 'archive', 'archives', 'old', 'tmp',
            'temp', 'temporary', 'cache', 'logs', 'log',
            
            # Security and access
            'auth', 'authentication', 'login', 'signin', 'logout',
            'register', 'registration', 'password', 'reset',
            'secure', 'security', 'ssl', 'cert', 'certificates',
            
            # Documentation
            'docs', 'documentation', 'help', 'manual', 'guide',
            'readme', 'changelog', 'license', 'api-docs',
            
            # Tools and utilities
            'tools', 'utilities', 'scripts', 'bin', 'cgi-bin',
            'phpmyadmin', 'adminer', 'webmail', 'ftp',
            
            # Framework specific
            'app', 'application', 'src', 'source', 'lib', 'libraries',
            'vendor', 'node_modules', 'bower_components',
            'public', 'private', 'protected', 'includes', 'inc'
        ]
        
        # Common filenames to check
        self.common_filenames = [
            # Configuration files
            'config.php', 'configuration.php', 'config.json', 'config.xml',
            'settings.php', 'settings.json', 'app.config', 'web.config',
            '.env', '.env.local', '.env.production', 'database.yml',
            
            # Index and main files
            'index.php', 'index.html', 'default.php', 'main.php',
            'home.php', 'welcome.php', 'start.php',
            
            # Admin files
            'admin.php', 'administrator.php', 'login.php', 'auth.php',
            'signin.php', 'dashboard.php', 'panel.php', 'control.php',
            
            # API files
            'api.php', 'rest.php', 'endpoint.php', 'service.php',
            'ajax.php', 'json.php', 'xml.php',
            
            # Database files
            'database.php', 'db.php', 'connection.php', 'connect.php',
            'sql.php', 'query.php', 'model.php',
            
            # Information files
            'info.php', 'phpinfo.php', 'test.php', 'debug.php',
            'status.php', 'health.php', 'version.php',
            
            # Common scripts
            'upload.php', 'download.php', 'file.php', 'image.php',
            'search.php', 'form.php', 'contact.php', 'mail.php',
            
            # Backup and temporary files
            'backup.php', 'backup.sql', 'dump.sql', 'export.php',
            'temp.php', 'tmp.php', 'cache.php', 'session.php',
            
            # Security files
            '.htaccess', '.htpasswd', 'robots.txt', 'sitemap.xml',
            'crossdomain.xml', 'security.txt', 'humans.txt',
            
            # JavaScript files
            'app.js', 'main.js', 'script.js', 'functions.js',
            'jquery.js', 'bootstrap.js', 'config.js', 'settings.js'
        ]
    
    async def scan_comprehensive_internal_pages(self) -> List[InternalPage]:
        """
        Perform comprehensive internal page discovery
        """
        logger.info("internal_scanner.starting", target=self.target_url)
        
        # Generate all possible URLs to check
        urls_to_check = await self._generate_target_urls()
        logger.info("internal_scanner.urls_generated", count=len(urls_to_check))
        
        # Scan URLs in batches for efficiency
        discovered_pages = await self._batch_scan_urls(urls_to_check)
        
        # Extract additional URLs from discovered pages
        additional_urls = await self._extract_urls_from_content(discovered_pages)
        if additional_urls:
            logger.info("internal_scanner.additional_urls_found", count=len(additional_urls))
            additional_pages = await self._batch_scan_urls(additional_urls)
            discovered_pages.extend(additional_pages)
        
        # Filter and categorize results
        self.discovered_pages = self._filter_and_categorize(discovered_pages)
        
        logger.info("internal_scanner.completed", 
                   total_discovered=len(self.discovered_pages),
                   accessible=len([p for p in self.discovered_pages if p.is_accessible]))
        
        return self.discovered_pages
    
    async def _generate_target_urls(self) -> List[str]:
        """Generate comprehensive list of URLs to check"""
        urls = set()
        
        # Add base URL
        urls.add(self.target_url)
        
        # Generate path-based URLs
        for path in self.path_patterns:
            urls.add(f"{self.target_url}/{path}")
            urls.add(f"{self.target_url}/{path}/")
            
            # Add common filenames in each path
            for filename in self.common_filenames[:20]:  # Limit to avoid explosion
                urls.add(f"{self.target_url}/{path}/{filename}")
        
        # Generate root-level file URLs
        for filename in self.common_filenames:
            urls.add(f"{self.target_url}/{filename}")
        
        # Generate extension-based URLs for each path
        for path in self.path_patterns[:10]:  # Limit paths for extension scanning
            for file_type, extensions in self.target_extensions.items():
                for ext in extensions[:3]:  # Limit extensions per type
                    urls.add(f"{self.target_url}/{path}/index{ext}")
                    urls.add(f"{self.target_url}/{path}/main{ext}")
                    urls.add(f"{self.target_url}/{path}/app{ext}")
        
        # Generate common file patterns
        common_patterns = [
            'config', 'admin', 'login', 'dashboard', 'api', 'upload',
            'download', 'search', 'contact', 'about', 'info'
        ]
        
        for pattern in common_patterns:
            for file_type, extensions in self.target_extensions.items():
                for ext in extensions[:2]:
                    urls.add(f"{self.target_url}/{pattern}{ext}")
        
        return list(urls)
    
    async def _batch_scan_urls(self, urls: List[str], batch_size: int = 50) -> List[InternalPage]:
        """Scan URLs in optimized batches"""
        discovered_pages = []
        
        # Create HTTP session with optimizations
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ssl=self.ssl_context,
            enable_cleanup_closed=True
        )
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': 'SiteMapGuard-InternalScanner/4.0'}
        ) as session:
            
            # Process URLs in batches
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i + batch_size]
                
                # Create tasks for concurrent scanning
                tasks = [self._scan_single_url(session, url) for url in batch]
                
                # Execute batch
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for result in batch_results:
                    if isinstance(result, InternalPage):
                        discovered_pages.append(result)
                
                # Small delay between batches to be respectful
                if i + batch_size < len(urls):
                    await asyncio.sleep(0.1)
        
        return discovered_pages
    
    async def _scan_single_url(self, session: aiohttp.ClientSession, url: str) -> Optional[InternalPage]:
        """Scan a single URL and return detailed information"""
        start_time = time.time()
        
        try:
            async with session.head(url, allow_redirects=False) as response:
                # Get basic information from HEAD request
                page_info = InternalPage(
                    url=url,
                    file_type=self._detect_file_type(url, response.headers),
                    status_code=response.status,
                    size_bytes=int(response.headers.get('content-length', 0)),
                    content_type=response.headers.get('content-type', ''),
                    last_modified=response.headers.get('last-modified'),
                    security_headers=self._extract_security_headers(response.headers),
                    response_time_ms=(time.time() - start_time) * 1000
                )
                
                # Check if page is accessible
                if response.status == 200:
                    page_info.is_accessible = True
                    
                    # For accessible pages, get content preview
                    if page_info.size_bytes < 1024 * 100:  # Only for files < 100KB
                        try:
                            async with session.get(url, allow_redirects=False) as get_response:
                                content = await get_response.text(errors='ignore')
                                page_info.content_preview = content[:500]  # First 500 chars
                        except:
                            pass
                
                elif response.status in [301, 302, 303, 307, 308]:
                    page_info.redirect_url = response.headers.get('location')
                
                return page_info
        
        except Exception as e:
            # Create entry for failed requests
            return InternalPage(
                url=url,
                file_type=self._detect_file_type(url),
                status_code=0,
                size_bytes=0,
                content_type='',
                response_time_ms=(time.time() - start_time) * 1000
            )
    
    def _detect_file_type(self, url: str, headers: Dict = None) -> str:
        """Detect file type from URL and headers"""
        # Try to detect from content-type header first
        if headers:
            content_type = headers.get('content-type', '').lower()
            if 'php' in content_type or 'php' in url:
                return 'php'
            elif 'javascript' in content_type or url.endswith(('.js', '.jsx')):
                return 'javascript'
            elif 'css' in content_type or url.endswith(('.css', '.scss')):
                return 'stylesheet'
            elif 'json' in content_type or url.endswith('.json'):
                return 'json'
            elif 'xml' in content_type or url.endswith('.xml'):
                return 'xml'
            elif 'html' in content_type:
                return 'html'
        
        # Detect from URL extension
        for file_type, extensions in self.target_extensions.items():
            for ext in extensions:
                if url.lower().endswith(ext):
                    return file_type
        
        # Detect from URL path patterns
        url_lower = url.lower()
        if '/admin' in url_lower or '/dashboard' in url_lower:
            return 'admin'
        elif '/api/' in url_lower or '/rest/' in url_lower:
            return 'api'
        elif '/upload' in url_lower or '/file' in url_lower:
            return 'upload'
        elif '/config' in url_lower or '/setting' in url_lower:
            return 'config'
        
        return 'unknown'
    
    def _extract_security_headers(self, headers: Dict) -> Dict[str, str]:
        """Extract security-relevant headers"""
        security_headers = {}
        
        security_header_names = [
            'x-frame-options', 'x-xss-protection', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy',
            'x-powered-by', 'server', 'x-generator'
        ]
        
        for header_name in security_header_names:
            if header_name in headers:
                security_headers[header_name] = headers[header_name]
        
        return security_headers
    
    async def _extract_urls_from_content(self, pages: List[InternalPage]) -> List[str]:
        """Extract additional URLs from page content"""
        urls = set()
        
        for page in pages:
            if page.is_accessible and page.content_preview:
                # Extract URLs from content using regex
                content = page.content_preview
                
                # Find href attributes
                href_matches = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
                
                # Find src attributes
                src_matches = re.findall(r'src=["\']([^"\']+)["\']', content, re.IGNORECASE)
                
                # Find action attributes
                action_matches = re.findall(r'action=["\']([^"\']+)["\']', content, re.IGNORECASE)
                
                # Find JavaScript URLs
                js_url_matches = re.findall(r'["\']([^"\']*\.(?:php|js|css|json)[^"\']*)["\']', content)
                
                all_matches = href_matches + src_matches + action_matches + js_url_matches
                
                for match in all_matches:
                    try:
                        # Convert relative URLs to absolute
                        if match.startswith('/'):
                            full_url = f"{self.target_url.split('/')[0]}//{self.target_url.split('//')[1].split('/')[0]}{match}"
                        elif match.startswith('http'):
                            full_url = match
                        elif not match.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                            full_url = urljoin(page.url, match)
                        else:
                            continue
                        
                        # Only add URLs from same domain
                        if self.domain in full_url:
                            urls.add(full_url)
                    except:
                        continue
        
        return list(urls)
    
    def _filter_and_categorize(self, pages: List[InternalPage]) -> List[InternalPage]:
        """Filter and categorize discovered pages"""
        filtered_pages = []
        
        # Remove duplicates and filter
        seen_urls = set()
        for page in pages:
            if page.url not in seen_urls:
                seen_urls.add(page.url)
                
                # Skip clearly non-existent pages
                if page.status_code == 404:
                    continue
                
                # Skip very large files to avoid memory issues
                if page.size_bytes > 10 * 1024 * 1024:  # 10MB
                    continue
                
                filtered_pages.append(page)
        
        # Sort by accessibility and file type
        filtered_pages.sort(key=lambda p: (
            0 if p.is_accessible else 1,  # Accessible first
            0 if p.file_type in ['php', 'javascript', 'api'] else 1,  # Important types first
            p.url
        ))
        
        return filtered_pages
    
    def generate_clickable_report(self, output_path: str) -> str:
        """Generate an HTML report with clickable links"""
        html_content = self._create_html_report()
        
        # Save HTML report
        html_path = Path(output_path).parent / f"{Path(output_path).stem}_clickable.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(html_path)
    
    def _create_html_report(self) -> str:
        """Create HTML report with clickable links and detailed information"""
        
        # Group pages by type
        pages_by_type = {}
        for page in self.discovered_pages:
            if page.file_type not in pages_by_type:
                pages_by_type[page.file_type] = []
            pages_by_type[page.file_type].append(page)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internal Pages Report - {self.domain}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            flex-wrap: wrap;
        }}
        .stat-box {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 10px;
            text-align: center;
            min-width: 150px;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .file-type-section {{
            background: white;
            margin: 20px 0;
            border-radius: 10px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .file-type-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 2px solid #e9ecef;
            font-weight: bold;
            font-size: 1.2em;
        }}
        .page-list {{
            padding: 0;
            margin: 0;
            list-style: none;
        }}
        .page-item {{
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
            transition: background-color 0.3s;
        }}
        .page-item:hover {{
            background-color: #f8f9fa;
        }}
        .page-url {{
            font-size: 1.1em;
            margin-bottom: 8px;
        }}
        .page-url a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }}
        .page-url a:hover {{
            text-decoration: underline;
        }}
        .page-details {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 0.9em;
            color: #666;
        }}
        .detail-item {{
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid #e9ecef;
        }}
        .status-200 {{ background-color: #d4edda; border-color: #c3e6cb; color: #155724; }}
        .status-300 {{ background-color: #fff3cd; border-color: #ffeaa7; color: #856404; }}
        .status-400 {{ background-color: #f8d7da; border-color: #f5c6cb; color: #721c24; }}
        .status-500 {{ background-color: #f8d7da; border-color: #f5c6cb; color: #721c24; }}
        .content-preview {{
            margin-top: 10px;
            padding: 10px;
            background: #f1f3f4;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.8em;
            max-height: 100px;
            overflow-y: auto;
            white-space: pre-wrap;
        }}
        .security-headers {{
            margin-top: 10px;
        }}
        .security-header {{
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            color: #0d47a1;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-right: 5px;
            display: inline-block;
            margin-bottom: 3px;
        }}
        .filter-buttons {{
            margin: 20px 0;
            text-align: center;
        }}
        .filter-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            margin: 5px;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }}
        .filter-btn:hover {{
            background: #5a6fd8;
        }}
        .filter-btn.active {{
            background: #4c63d2;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Internal Pages Discovery Report</h1>
        <h2>{self.domain}</h2>
        <p>Comprehensive scan of internal pages, scripts, and resources</p>
    </div>

    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">{len(self.discovered_pages)}</div>
            <div>Total Pages</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{len([p for p in self.discovered_pages if p.is_accessible])}</div>
            <div>Accessible</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{len(set(p.file_type for p in self.discovered_pages))}</div>
            <div>File Types</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{len([p for p in self.discovered_pages if p.file_type in ['php', 'javascript']])}</div>
            <div>Scripts</div>
        </div>
    </div>

    <div class="filter-buttons">
        <button class="filter-btn active" onclick="showAll()">All Pages</button>
        <button class="filter-btn" onclick="filterByType('accessible')">Accessible Only</button>
        <button class="filter-btn" onclick="filterByType('php')">PHP Files</button>
        <button class="filter-btn" onclick="filterByType('javascript')">JavaScript</button>
        <button class="filter-btn" onclick="filterByType('admin')">Admin Pages</button>
    </div>
'''
        
        # Add sections for each file type
        for file_type, pages in sorted(pages_by_type.items()):
            html += f'''
    <div class="file-type-section" data-type="{file_type}">
        <div class="file-type-header">
            {file_type.upper()} Files ({len(pages)} found)
        </div>
        <ul class="page-list">
'''
            
            for page in pages:
                status_class = f"status-{str(page.status_code)[0]}00" if page.status_code else "status-000"
                
                html += f'''
            <li class="page-item {'accessible' if page.is_accessible else 'inaccessible'}" data-accessible="{page.is_accessible}" data-type="{page.file_type}">
                <div class="page-url">
                    <a href="{page.url}" target="_blank" rel="noopener">{page.url}</a>
                </div>
                <div class="page-details">
                    <span class="detail-item {status_class}">Status: {page.status_code}</span>
                    <span class="detail-item">Type: {page.file_type}</span>
                    <span class="detail-item">Size: {self._format_file_size(page.size_bytes)}</span>
                    <span class="detail-item">Response: {page.response_time_ms:.0f}ms</span>
                    {f'<span class="detail-item">Redirect: {page.redirect_url}</span>' if page.redirect_url else ''}
                </div>
'''
                
                # Add security headers if available
                if page.security_headers:
                    html += '<div class="security-headers">'
                    for header, value in page.security_headers.items():
                        html += f'<span class="security-header">{header}: {value[:50]}</span>'
                    html += '</div>'
                
                # Add content preview if available
                if page.content_preview:
                    preview = page.content_preview.replace('<', '&lt;').replace('>', '&gt;')
                    html += f'<div class="content-preview">{preview}</div>'
                
                html += '</li>'
            
            html += '''
        </ul>
    </div>
'''
        
        html += '''
    <script>
        function showAll() {
            document.querySelectorAll('.page-item').forEach(item => item.style.display = 'block');
            document.querySelectorAll('.file-type-section').forEach(section => section.style.display = 'block');
            setActiveButton(0);
        }
        
        function filterByType(type) {
            if (type === 'accessible') {
                document.querySelectorAll('.page-item').forEach(item => {
                    item.style.display = item.dataset.accessible === 'true' ? 'block' : 'none';
                });
                document.querySelectorAll('.file-type-section').forEach(section => section.style.display = 'block');
                setActiveButton(1);
            } else {
                document.querySelectorAll('.page-item').forEach(item => {
                    item.style.display = item.dataset.type === type ? 'block' : 'none';
                });
                document.querySelectorAll('.file-type-section').forEach(section => {
                    const hasVisibleItems = section.querySelectorAll('.page-item[data-type="' + type + '"]').length > 0;
                    section.style.display = hasVisibleItems ? 'block' : 'none';
                });
                const buttonIndex = {'php': 2, 'javascript': 3, 'admin': 4}[type] || 0;
                setActiveButton(buttonIndex);
            }
        }
        
        function setActiveButton(index) {
            document.querySelectorAll('.filter-btn').forEach((btn, i) => {
                btn.classList.toggle('active', i === index);
            });
        }
    </script>
</body>
</html>'''
        
        return html
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB']
        size = float(size_bytes)
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.1f} {units[unit_index]}"

# High-level function for easy integration
async def discover_internal_pages(target_url: str, output_dir: str = "./reports") -> Dict[str, Any]:
    """
    Discover internal pages and generate both text and HTML reports
    """
    scanner = ComprehensiveInternalScanner(target_url)
    
    # Perform comprehensive scan
    discovered_pages = await scanner.scan_comprehensive_internal_pages()
    
    # Generate reports
    domain = urlparse(target_url).netloc
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Text report (original format)
    text_report_path = Path(output_dir) / f"{domain}_internal_pages_{timestamp}.txt"
    
    # HTML report (clickable)
    html_report_path = scanner.generate_clickable_report(str(text_report_path))
    
    # Generate enhanced text report
    text_content = _generate_enhanced_text_report(discovered_pages, target_url)
    with open(text_report_path, 'w', encoding='utf-8') as f:
        f.write(text_content)
    
    return {
        'discovered_pages': discovered_pages,
        'total_pages': len(discovered_pages),
        'accessible_pages': len([p for p in discovered_pages if p.is_accessible]),
        'text_report_path': str(text_report_path),
        'html_report_path': html_report_path,
        'file_types_found': list(set(p.file_type for p in discovered_pages))
    }

def _generate_enhanced_text_report(pages: List[InternalPage], target_url: str) -> str:
    """Generate enhanced text report with clickable URLs"""
    lines = []
    domain = urlparse(target_url).netloc
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    lines.append("=" * 100)
    lines.append("INTERNAL PAGES DISCOVERY REPORT")
    lines.append("=" * 100)
    lines.append(f"Target Domain: {domain}")
    lines.append(f"Scan Date: {timestamp}")
    lines.append(f"Total Pages Found: {len(pages)}")
    lines.append(f"Accessible Pages: {len([p for p in pages if p.is_accessible])}")
    lines.append(f"File Types: {', '.join(set(p.file_type for p in pages))}")
    lines.append("=" * 100)
    lines.append("")
    
    lines.append("FORMAT: URL | Status | File Type | Size | Access | Redirect")
    lines.append("-" * 100)
    
    # Group by accessibility and file type
    accessible = [p for p in pages if p.is_accessible]
    inaccessible = [p for p in pages if not p.is_accessible and p.status_code != 404]
    
    if accessible:
        lines.append("")
        lines.append("ACCESSIBLE PAGES:")
        lines.append("-" * 50)
        
        for page in accessible:
            status = page.status_code
            file_type = page.file_type
            size = page.size_bytes
            size_str = f"{size} bytes" if size < 1024 else f"{size//1024} KB"
            redirect = page.redirect_url if page.redirect_url else "none"
            
            line = f"{page.url:<80} | {status:<6} | {file_type:<12} | {size_str:<10} | YES | {redirect}"
            lines.append(line)
    
    if inaccessible:
        lines.append("")
        lines.append("DISCOVERED BUT INACCESSIBLE:")
        lines.append("-" * 50)
        
        for page in inaccessible:
            status = page.status_code if page.status_code else "ERROR"
            file_type = page.file_type
            redirect = page.redirect_url if page.redirect_url else "none"
            
            line = f"{page.url:<80} | {status:<6} | {file_type:<12} | {'0 bytes':<10} | NO  | {redirect}"
            lines.append(line)
    
    lines.append("")
    lines.append("-" * 100)
    lines.append("SUMMARY BY FILE TYPE:")
    lines.append("-" * 100)
    
    # Count by file type
    type_counts = {}
    for page in pages:
        file_type = page.file_type
        if file_type not in type_counts:
            type_counts[file_type] = {'total': 0, 'accessible': 0}
        type_counts[file_type]['total'] += 1
        if page.is_accessible:
            type_counts[file_type]['accessible'] += 1
    
    for file_type, counts in sorted(type_counts.items()):
        lines.append(f"{file_type.upper():<15}: {counts['total']} found, {counts['accessible']} accessible")
    
    lines.append("")
    lines.append("=" * 100)
    lines.append("NOTE: Use the HTML report for clickable links and detailed analysis")
    lines.append("=" * 100)
    
    return "\n".join(lines)