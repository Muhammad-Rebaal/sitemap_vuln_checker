# SiteMap Guard Enhanced Features - Usage Guide

## What's New ✨

Your SiteMap Guard tool has been enhanced with exactly the features you requested:

### 1. Enhanced Report Format
- **URL | Status | Classification | Redirect** - Exactly as requested
- **Domain-based naming**: `habib.edu.pk_report_20241207_143022.txt`
- **Vulnerability classification**: URLs marked as 'clean' or 'virus'

### 2. Comprehensive URL Discovery
- Finds ALL links and redirects on the target domain
- Multiple discovery methods (robots.txt, sitemaps, common paths, link extraction)
- Technology-aware discovery (WordPress, Laravel, Django, etc.)

### 3. Real-time Vulnerability Analysis
- Checks each URL for security issues
- Classifies based on actual scan results
- Tracks redirects and final destinations

## Quick Start 🚀

### Method 1: Enhanced Sitemap Only (Fastest)

```bash
# Generate enhanced sitemap report only
python -m sitemap_guard sitemap https://habib.edu.pk --output ./reports
```

### Method 2: Full Security Scan + Enhanced Report

```bash
# Complete vulnerability scan + enhanced sitemap
python -m sitemap_guard scan https://habib.edu.pk --output ./reports
```

### Method 3: Web Interface

```bash
# Start web interface
streamlit run app.py
# Open browser: http://localhost:8501
# Enter URL and click "Launch Scan"
```

### Method 4: API Mode

```bash
# Terminal 1: Start API server
python -m sitemap_guard serve

# Terminal 2: Make request
curl -X POST "http://localhost:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://habib.edu.pk"}'
```

## Sample Output 📊

For input URL `https://habib.edu.pk`, you'll get:

**File**: `habib.edu.pk_report_20241207_143022.txt`

```
===============================================================================
ENHANCED SITEMAP VULNERABILITY REPORT
===============================================================================
Target Domain: habib.edu.pk
Scan Date: 2024-12-07 14:30:22
Total URLs: 147
Clean URLs: 134
Vulnerable URLs: 13
===============================================================================

FORMAT: URL | Status | Classification | Redirect
----------------------------------------------------------------------------------------------------
https://habib.edu.pk/                           | 200        | clean      | none
https://habib.edu.pk/admin/                     | 403        | virus      | none
https://habib.edu.pk/wp-login.php               | 200        | virus      | none
https://habib.edu.pk/about/                     | 200        | clean      | none
https://habib.edu.pk/contact/                   | 200        | clean      | none
https://habib.edu.pk/old-page/                  | 301        | clean      | https://habib.edu.pk/new-page/
https://habib.edu.pk/config.php                 | 403        | virus      | none
https://habib.edu.pk/api/                       | 200        | clean      | none
```

## Understanding the Output 📝

### Status Column
- **200**: OK (working page)
- **301/302**: Redirect
- **403**: Forbidden
- **404**: Not found
- **500**: Server error
- **timeout**: Request timed out
- **error**: Connection failed

### Classification Column
- **clean**: No vulnerabilities detected
- **virus**: Vulnerabilities found (security headers, exposed files, etc.)

### Redirect Column
- **none**: No redirect
- **URL**: Shows where the page redirects to

## Features Breakdown 🔧

### URL Discovery Methods
1. **Robots.txt**: Extracts sitemap URLs and disallowed paths
2. **Sitemap.xml**: Parses XML sitemaps for URLs
3. **Common Paths**: Tests 100+ common web paths
4. **Link Extraction**: Follows links from main pages
5. **Tech Stack Awareness**: Adds paths based on detected technologies

### Vulnerability Detection
- **Security Headers**: Missing or misconfigured headers
- **Exposed Files**: Config files, backups, admin panels
- **Suspicious Patterns**: Potentially dangerous URLs
- **Response Analysis**: Error pages, suspicious content

### Performance Features
- **Concurrent Processing**: Fast multi-threaded scanning
- **SSL Resilience**: Handles problematic certificates
- **Rate Limiting**: Respects server resources
- **Error Handling**: Graceful failure recovery

## Installation Requirements 📋

Make sure you have the required dependencies:

```bash
# Install/update dependencies
pip install -r requirements.txt

# Or if using Poetry/pyproject.toml
pip install -e .
```

Key dependencies:
- `aiohttp` (for async HTTP requests)
- `structlog` (for logging)
- `pathlib` (for file handling)

## Troubleshooting 🔧

### Common Issues

1. **DNS/Connection Errors**: 
   - Normal for unreachable domains
   - The tool will still generate reports with discovered URLs

2. **SSL Certificate Issues**:
   - The tool automatically handles problematic SSL certificates
   - Uses custom SSL context for maximum compatibility

3. **Large Sites**:
   - Processing is batched to avoid overwhelming servers
   - Reports may take longer for sites with many URLs

### Logging

The tool uses structured logging. To see detailed logs:
- Debug messages show discovery progress
- Info messages show major milestones
- Warnings indicate potential issues

## Customization 🛠️

You can customize the enhanced reporter by modifying:

1. **Common Paths**: Edit `COMMON_PATHS` in the reporter
2. **Batch Size**: Adjust concurrent request limits
3. **Timeout Values**: Modify request timeouts
4. **Discovery Methods**: Enable/disable specific discovery techniques

## Integration 🔌

The enhanced reporter integrates seamlessly with:

- **Existing CLI**: Works with current commands
- **Web Interface**: New tab in Streamlit app
- **API**: Adds `enhanced_report_path` to responses
- **Pipeline**: Automatic generation during scans

## Security Considerations 🔒

- **Rate Limiting**: Built-in delays to avoid overwhelming targets
- **Ethical Scanning**: Only scans provided domains
- **SSL Handling**: Secure by default with fallback options
- **Error Boundaries**: Isolated failure handling

## Next Steps 🎯

1. **Run your first scan**: `python -m sitemap_guard sitemap https://your-domain.com`
2. **Check the reports folder**: Look for `domain_report_datetime.txt`
3. **Review the results**: Focus on 'virus' classified URLs
4. **Use for security audits**: Regular monitoring of your domains

Your enhanced SiteMap Guard is ready to use with exactly the format and functionality you requested! 🎉