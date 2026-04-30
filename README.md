# 🛡️ SiteMap Guard v3
**The Ultra-Fast, Offline-First Security Orchestrator & Intelligence Mapper**

SiteMap Guard v3 is a production-grade, open-source security tool designed for high-performance website reconnaissance and vulnerability auditing. It automates the discovery of hidden assets, probes for live services, and executes deep vulnerability scans—all while maintaining an **entirely offline-first** philosophy for privacy and speed.

---

## 🚀 Key Features

### 1. 🤖 Autonomous Asset Discovery
*   **Recursive Sitemap Parsing**: Deep-dives into XML sitemaps and `robots.txt` to map the entire application structure.
*   **Resilient Probing**: Uses **TLS Impersonation (`-tlsi`)** to bypass server-side blocks and SSL handshake failures (`SSLEOFError`).
*   **Probing Fallback**: Intelligent logic ensures that even if a host fails a ping/probe, the scan continues using discovered sitemap URLs as a fallback.

### 2. 🔍 Deep Vulnerability Scanning
*   **Nuclei Integration**: Powered by [Nuclei](https://github.com/projectdiscovery/nuclei), supporting 5,000+ community-maintained security templates.
*   **High Concurrency**: Tuned for asynchronous execution, capable of scanning hundreds of endpoints in seconds.
*   **Smart Deduplication**: Automatically cleans and groups repetitive findings into a concise, actionable report.

### 3. 🗺️ Intelligence Flowcharts (V3 Exclusive)
*   **Interactive Topology**: Generates a self-contained HTML graph of your site structure.
*   **Security Heatmap**: Nodes are color-coded by severity (**Red** for Critical, **Yellow** for Medium, **Blue** for Info).
*   **Exploded Insights**: "Explodes" tech stacks and vulnerabilities into the visual tree so you can see findings at a glance without digging through logs.
*   **Fully Offline**: Embedded ECharts engine means reports work perfectly in air-gapped environments.

### 4. 🛡️ Privacy-First Reputation
*   **Zero-API Threat Scanning**: Uses Rust-powered **Bloom Filters** to check URLs against community threat feeds (URLHaus, OpenPhish) locally.
*   **No Data Leaks**: Your target URLs are never sent to third-party services like VirusTotal or Google Safe Browsing.

---

## 🏗️ Core Components & Architecture

| Module | Purpose | Key Logic |
|---|---|---|
| **`cli.py`** | Entry Point | Click-based interface, handles Rich console tables and Windows UTF-8 encoding. |
| **`pipeline.py`** | Orchestrator | Manages the flow: `Discovery` ➔ `httpx Probe` ➔ `Nuclei Scan` ➔ `Threat Feed Lookup`. |
| **`flowchart.py`** | Visualization | Transforms JSON findings into a high-fidelity D3/ECharts intelligence map. |
| **`threat_feeds.py`** | Local Intel | Handles JIT downloading and caching of malware/phishing feeds into local Bloom filters. |
| **`config.py`** | Configuration | Centralized Pydantic-based settings for timeouts, concurrency, and binary paths. |

---

## ⚡ Technical Specifications

*   **Engine**: Python 3.10+ (Asynchronous / `asyncio`)
*   **Reputation**: Rust-based `rbloom` for O(1) membership testing.
*   **Visuals**: Apache ECharts (Minified & Embedded).
*   **Binaries**: Utilizes pre-compiled Go binaries for `nuclei` and `httpx`.

---

## 📖 Quick Start

### Installation
```bash
# Clone and Install
git clone https://github.com/sitemap-guard/sitemap-guard.git
cd sitemap-guard
pip install -e .

# Ensure binaries are in ./bin/
# nuclei.exe, httpx.exe, etc.
```

### Run a Standard Scan
```bash
python -m sitemap_guard.cli scan https://target-website.com
```

### Review Results
*   **Terminal**: Real-time summary tables for Tech Stack and Vulnerabilities.
*   **Report**: Check `./reports/sitemap_flowchart.html` for the interactive intelligence graph.
*   **Logs**: Deep JSON logs in `./reports/nuclei_out.json` and `./reports/probe_results.json`.

---

## 🔧 Windows Optimization
SiteMap Guard is uniquely optimized for Windows security environments:
*   **UTF-8 Forced**: Automatically reconfigures `sys.stdout` to prevent `UnicodeEncodeError` on complex findings.
*   **Binary Management**: Seamlessly invokes `.exe` binaries from the local `bin/` directory.

---

## 📜 Ethical Use & Disclaimer
This tool is designed for **authorized security testing only**. Always respect `robots.txt`, utilize appropriate rate limiting, and only scan targets you explicitly own or have permission to audit.

Developed with ❤️ by the SiteMap Guard Team.
