"""
Comprehensive reporter that combines enhanced sitemap with internal page discovery
Generates both text and HTML reports with clickable links for all discovered pages
"""
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import structlog

logger = structlog.get_logger()

class ComprehensiveReporter:
    """
    Comprehensive reporter that generates multiple report formats:
    1. Original text format: URL | Status | Classification | Redirect
    2. HTML report with clickable links and detailed analysis
    3. Internal pages discovery with PHP, JS, and other file types
    """
    
    def __init__(self, target_url: str, output_dir: str = "./reports"):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    async def generate_comprehensive_reports(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive reports including internal page discovery
        """
        logger.info("comprehensive_reporter.starting", domain=self.domain)
        
        # Import internal scanner here to avoid circular imports
        from sitemap_guard.discovery.internal_scanner import discover_internal_pages
        
        # Run internal page discovery
        internal_results = await discover_internal_pages(self.target_url, str(self.output_dir))
        
        # Generate enhanced sitemap report (original format)
        enhanced_report_path = await self._generate_enhanced_sitemap_report(scan_results, internal_results)
        
        # Generate comprehensive HTML report
        html_report_path = self._generate_comprehensive_html_report(scan_results, internal_results)
        
        # Generate summary report
        summary_report_path = self._generate_summary_report(scan_results, internal_results)
        
        logger.info("comprehensive_reporter.completed",
                   enhanced_report=enhanced_report_path,
                   html_report=html_report_path,
                   summary_report=summary_report_path)
        
        return {
            'enhanced_report_path': enhanced_report_path,
            'html_report_path': html_report_path,
            'summary_report_path': summary_report_path,
            'internal_pages_found': internal_results['total_pages'],
            'accessible_internal_pages': internal_results['accessible_pages'],
            'file_types_discovered': internal_results['file_types_found']
        }
    
    async def _generate_enhanced_sitemap_report(self, scan_results: Dict[str, Any], internal_results: Dict[str, Any]) -> str:
        """Generate the enhanced sitemap report in the original requested format"""
        
        # Combine regular scan results with internal pages
        all_urls = self._combine_all_discovered_urls(scan_results, internal_results)
        
        # Process URLs for vulnerability classification
        classified_urls = self._classify_all_urls(all_urls, scan_results, internal_results)
        
        # Generate report filename
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        clean_domain = self.domain.replace(':', '_').replace('/', '_')
        filename = f"{clean_domain}_enhanced_report_{timestamp}.txt"
        report_path = self.output_dir / filename
        
        # Generate report content
        report_content = self._create_enhanced_report_content(classified_urls, scan_results, internal_results, now)
        
        # Write report
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return str(report_path)
    
    def _combine_all_discovered_urls(self, scan_results: Dict[str, Any], internal_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Combine URLs from scan results and internal discovery"""
        all_urls = []
        
        # Add URLs from live targets
        live_targets = scan_results.get('live_targets', [])
        for target in live_targets:
            all_urls.append({
                'url': target.get('url'),
                'status': target.get('status', 0),
                'source': 'live_scan',
                'redirect': '',
                'file_type': 'web_page',
                'size': target.get('content_length', 0),
                'response_time': target.get('response_time', 0)
            })
        
        # Add internal pages
        internal_pages = internal_results.get('discovered_pages', [])
        for page in internal_pages:
            all_urls.append({
                'url': page.url,
                'status': page.status_code,
                'source': 'internal_discovery',
                'redirect': page.redirect_url or '',
                'file_type': page.file_type,
                'size': page.size_bytes,
                'response_time': page.response_time_ms,
                'is_accessible': page.is_accessible,
                'content_preview': getattr(page, 'content_preview', '')
            })
        
        return all_urls
    
    def _classify_all_urls(self, urls: List[Dict[str, Any]], scan_results: Dict[str, Any], internal_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Classify all URLs as clean or virus based on findings"""
        
        # Get all vulnerable URLs from findings
        vulnerable_urls = set()
        
        for finding_type in ['header_findings', 'nuclei_findings', 'threat_findings', 'js_secrets', 'plugin_findings', 'advanced_findings']:
            findings = scan_results.get(finding_type, [])
            for finding in findings:
                if finding.get('url'):
                    vulnerable_urls.add(finding['url'])
        
        # Classify each URL
        for url_data in urls:
            url = url_data['url']
            classification = 'clean'
            
            # Check if URL has known vulnerabilities
            if url in vulnerable_urls:
                classification = 'virus'
            
            # Check for suspicious file types or paths
            elif self._is_suspicious_url_pattern(url, url_data):
                classification = 'virus'
            
            # Check for error status codes that might indicate issues
            elif url_data.get('status') in [403, 500, 501, 502, 503]:
                classification = 'suspicious'
            
            url_data['classification'] = classification
        
        return urls
    
    def _is_suspicious_url_pattern(self, url: str, url_data: Dict[str, Any]) -> bool:
        """Check if URL has suspicious patterns"""
        
        url_lower = url.lower()
        file_type = url_data.get('file_type', '')
        
        # Check for exposed configuration files
        if file_type in ['config', 'backup', 'env']:
            return True
        
        # Check for database files
        if any(ext in url_lower for ext in ['.sql', '.db', '.sqlite', '.mdb']):
            return True
        
        # Check for backup files
        if any(ext in url_lower for ext in ['.bak', '.backup', '.old', '.orig']):
            return True
        
        # Check for log files
        if any(pattern in url_lower for pattern in ['/log', '.log', '/logs', '/debug']):
            return True
        
        # Check for admin panels with weak authentication
        if any(pattern in url_lower for pattern in ['/admin', '/administrator', '/phpmyadmin']):
            if url_data.get('status') == 200:  # Accessible admin panel
                return True
        
        # Check for development files
        if any(pattern in url_lower for pattern in ['/test', '/dev', '/debug', 'phpinfo']):
            return True
        
        return False
    
    def _create_enhanced_report_content(self, urls: List[Dict[str, Any]], scan_results: Dict[str, Any], internal_results: Dict[str, Any], timestamp: datetime) -> str:
        """Create the enhanced report content in the requested format"""
        
        lines = []
        lines.append("=" * 120)
        lines.append("COMPREHENSIVE SITEMAP & INTERNAL PAGES REPORT")
        lines.append("=" * 120)
        lines.append(f"Target Domain: {self.domain}")
        lines.append(f"Scan Date: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total URLs Found: {len(urls)}")
        lines.append(f"Clean URLs: {len([u for u in urls if u.get('classification') == 'clean'])}")
        lines.append(f"Vulnerable URLs: {len([u for u in urls if u.get('classification') == 'virus'])}")
        lines.append(f"Suspicious URLs: {len([u for u in urls if u.get('classification') == 'suspicious'])}")
        lines.append(f"Internal Pages: {internal_results.get('total_pages', 0)}")
        lines.append(f"Accessible Internal Pages: {internal_results.get('accessible_pages', 0)}")
        lines.append(f"File Types Discovered: {', '.join(internal_results.get('file_types_found', []))}")
        lines.append("=" * 120)
        lines.append("")
        
        lines.append("FORMAT: URL | Status | Classification | Redirect | File Type | Size")
        lines.append("-" * 120)
        lines.append("")
        
        # Sort URLs by classification (virus first), then by status, then alphabetically
        sorted_urls = sorted(urls, key=lambda x: (
            0 if x.get('classification') == 'virus' else 1 if x.get('classification') == 'suspicious' else 2,
            -(x.get('status', 0)),  # Higher status codes first
            x.get('url', '')
        ))
        
        # Group by classification for better readability
        virus_urls = [u for u in sorted_urls if u.get('classification') == 'virus']
        suspicious_urls = [u for u in sorted_urls if u.get('classification') == 'suspicious']
        clean_urls = [u for u in sorted_urls if u.get('classification') == 'clean']
        
        if virus_urls:
            lines.append("VULNERABLE/DANGEROUS URLs:")
            lines.append("-" * 60)
            for url_data in virus_urls:
                lines.append(self._format_url_line(url_data))
            lines.append("")
        
        if suspicious_urls:
            lines.append("SUSPICIOUS URLs:")
            lines.append("-" * 60)
            for url_data in suspicious_urls:
                lines.append(self._format_url_line(url_data))
            lines.append("")
        
        lines.append("CLEAN URLs:")
        lines.append("-" * 60)
        for url_data in clean_urls[:100]:  # Limit clean URLs to avoid huge reports
            lines.append(self._format_url_line(url_data))
        
        if len(clean_urls) > 100:
            lines.append(f"... and {len(clean_urls) - 100} more clean URLs")
        
        lines.append("")
        lines.append("-" * 120)
        lines.append("SUMMARY BY FILE TYPE:")
        lines.append("-" * 120)
        
        # Summarize by file type
        type_summary = {}
        for url_data in urls:
            file_type = url_data.get('file_type', 'unknown')
            classification = url_data.get('classification', 'unknown')
            
            if file_type not in type_summary:
                type_summary[file_type] = {'total': 0, 'clean': 0, 'virus': 0, 'suspicious': 0}
            
            type_summary[file_type]['total'] += 1
            type_summary[file_type][classification] += 1
        
        for file_type, counts in sorted(type_summary.items()):
            lines.append(f"{file_type.upper():<15}: {counts['total']} total | "
                        f"{counts['clean']} clean | {counts['virus']} virus | {counts['suspicious']} suspicious")
        
        lines.append("")
        lines.append("=" * 120)
        lines.append("LEGEND:")
        lines.append("Status: HTTP status code (200=OK, 301/302=Redirect, 403=Forbidden, 404=Not Found, etc.)")
        lines.append("Classification: 'clean'=safe, 'virus'=vulnerabilities detected, 'suspicious'=potential issues")
        lines.append("Redirect: Target URL if redirect detected, 'none' if no redirect")
        lines.append("File Type: Detected file/page type (php, javascript, admin, config, etc.)")
        lines.append("Size: File size in bytes")
        lines.append("")
        lines.append("NOTE: HTML report with clickable links available for detailed analysis")
        lines.append("=" * 120)
        lines.append(f"Report generated by SiteMap Guard Comprehensive Scanner v4.0")
        lines.append(f"Timestamp: {timestamp.isoformat()}")
        lines.append("=" * 120)
        
        return '\n'.join(lines)
    
    def _format_url_line(self, url_data: Dict[str, Any]) -> str:
        """Format a single URL line in the report"""
        url = url_data.get('url', '')
        status = url_data.get('status', 0)
        classification = url_data.get('classification', 'unknown')
        redirect = url_data.get('redirect', '') or 'none'
        file_type = url_data.get('file_type', 'unknown')
        size = url_data.get('size', 0)
        
        # Truncate long URLs and redirects for readability
        if len(url) > 70:
            url = url[:67] + '...'
        if len(redirect) > 50 and redirect != 'none':
            redirect = redirect[:47] + '...'
        
        # Format size
        if size > 1024 * 1024:
            size_str = f"{size // (1024 * 1024)}MB"
        elif size > 1024:
            size_str = f"{size // 1024}KB"
        else:
            size_str = f"{size}B"
        
        return f"{url:<70} | {status:<6} | {classification:<12} | {redirect:<50} | {file_type:<12} | {size_str}"
    
    def _generate_comprehensive_html_report(self, scan_results: Dict[str, Any], internal_results: Dict[str, Any]) -> str:
        """Generate comprehensive HTML report with clickable links"""
        
        # Use the HTML report from internal scanner as base
        html_report_path = internal_results.get('html_report_path')
        
        if html_report_path and Path(html_report_path).exists():
            # Enhance the existing HTML report
            return self._enhance_html_report(html_report_path, scan_results)
        else:
            # Create new HTML report
            return self._create_new_html_report(scan_results, internal_results)
    
    def _enhance_html_report(self, html_report_path: str, scan_results: Dict[str, Any]) -> str:
        """Enhance existing HTML report with vulnerability information"""
        
        try:
            # Read existing HTML
            with open(html_report_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Add vulnerability information
            vulnerability_section = self._create_vulnerability_html_section(scan_results)
            
            # Insert before closing body tag
            enhanced_html = html_content.replace('</body>', f'{vulnerability_section}</body>')
            
            # Save enhanced version
            enhanced_path = Path(html_report_path).parent / f"comprehensive_{Path(html_report_path).name}"
            with open(enhanced_path, 'w', encoding='utf-8') as f:
                f.write(enhanced_html)
            
            return str(enhanced_path)
            
        except Exception as e:
            logger.error("html_enhancement_failed", error=str(e))
            return html_report_path
    
    def _create_vulnerability_html_section(self, scan_results: Dict[str, Any]) -> str:
        """Create HTML section for vulnerability information"""
        
        html = '''
    <div class="file-type-section">
        <div class="file-type-header">
            Security Vulnerabilities Found
        </div>
        <ul class="page-list">
'''
        
        # Add vulnerability findings
        all_findings = []
        
        for finding_type in ['header_findings', 'nuclei_findings', 'threat_findings', 'js_secrets', 'plugin_findings']:
            findings = scan_results.get(finding_type, [])
            for finding in findings:
                all_findings.append({
                    'type': finding_type,
                    'url': finding.get('url', ''),
                    'name': finding.get('name', ''),
                    'severity': finding.get('severity', 'unknown'),
                    'details': finding.get('details', '')
                })
        
        for finding in all_findings[:50]:  # Limit to first 50 findings
            severity_class = f"status-{finding['severity']}"
            html += f'''
            <li class="page-item">
                <div class="page-url">
                    <a href="{finding['url']}" target="_blank" rel="noopener">{finding['url']}</a>
                </div>
                <div class="page-details">
                    <span class="detail-item {severity_class}">Severity: {finding['severity']}</span>
                    <span class="detail-item">Type: {finding['type']}</span>
                    <span class="detail-item">Finding: {finding['name']}</span>
                </div>
'''
            if finding['details']:
                html += f'<div class="content-preview">{finding["details"][:200]}...</div>'
            
            html += '</li>'
        
        html += '''
        </ul>
    </div>
'''
        
        return html
    
    def _create_new_html_report(self, scan_results: Dict[str, Any], internal_results: Dict[str, Any]) -> str:
        """Create new comprehensive HTML report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.domain}_comprehensive_{timestamp}.html"
        report_path = self.output_dir / filename
        
        # Simple HTML structure
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Report - {self.domain}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #333; color: white; padding: 20px; }}
        .section {{ margin: 20px 0; }}
        .url-list {{ list-style: none; padding: 0; }}
        .url-item {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; }}
        .virus {{ background: #ffe6e6; }}
        .clean {{ background: #e6ffe6; }}
        .suspicious {{ background: #fff3e6; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Comprehensive Security Report</h1>
        <h2>{self.domain}</h2>
    </div>
    
    <div class="section">
        <h3>Summary</h3>
        <p>Total URLs: {len(scan_results.get('live_targets', []))}</p>
        <p>Internal Pages: {internal_results.get('total_pages', 0)}</p>
    </div>
    
    <div class="section">
        <h3>Discovered URLs</h3>
        <ul class="url-list">
'''
        
        # Add URLs
        live_targets = scan_results.get('live_targets', [])
        for target in live_targets[:100]:  # Limit for performance
            url = target.get('url', '')
            status = target.get('status', 0)
            
            html_content += f'''
            <li class="url-item clean">
                <a href="{url}" target="_blank">{url}</a>
                <span style="float: right;">Status: {status}</span>
            </li>'''
        
        html_content += '''
        </ul>
    </div>
</body>
</html>'''
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(report_path)
    
    def _generate_summary_report(self, scan_results: Dict[str, Any], internal_results: Dict[str, Any]) -> str:
        """Generate executive summary report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.domain}_summary_{timestamp}.txt"
        report_path = self.output_dir / filename
        
        # Count findings
        total_findings = 0
        for finding_type in ['header_findings', 'nuclei_findings', 'threat_findings', 'js_secrets', 'plugin_findings']:
            total_findings += len(scan_results.get(finding_type, []))
        
        content = f'''
EXECUTIVE SUMMARY - SECURITY SCAN REPORT
========================================

Target: {self.domain}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OVERVIEW
--------
Total URLs Discovered: {len(scan_results.get('live_targets', []))}
Internal Pages Found: {internal_results.get('total_pages', 0)}
Accessible Internal Pages: {internal_results.get('accessible_pages', 0)}
Security Findings: {total_findings}

FILE TYPES DISCOVERED
--------------------
{', '.join(internal_results.get('file_types_found', []))}

RISK ASSESSMENT
--------------
Based on the comprehensive scan, this assessment covers:
- Web application security
- Exposed internal files
- Configuration vulnerabilities  
- Administrative interface exposure

Recommendation: Review all flagged items and implement appropriate security measures.

For detailed technical findings, see the comprehensive report.
'''
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(report_path)

# High-level function for integration
async def generate_comprehensive_reports(target_url: str, scan_results: Dict[str, Any], output_dir: str = "./reports") -> Dict[str, Any]:
    """
    Generate comprehensive reports including internal page discovery
    """
    reporter = ComprehensiveReporter(target_url, output_dir)
    return await reporter.generate_comprehensive_reports(scan_results)