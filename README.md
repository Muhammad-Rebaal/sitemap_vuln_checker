# 🛡️ SiteMap Guard

**An Autonomous, Offline-First Web Vulnerability & Sitemap Scanner**

SiteMap Guard is a professional-grade security intelligence platform built to bridge the gap between simple sitemap crawling and deep, context-aware vulnerability scanning. It automatically discovers endpoints, bypasses legacy TLS restrictions, fingerprints web technologies, harvests embedded secrets, and generates highly actionable security reports.

---

## 🚀 Features at a Glance

*   **Deep Endpoint Discovery:** Combines active probing (robots.txt, sitemaps, tech-aware wordlists) with **Passive Reconnaissance** (Wayback Machine, CommonCrawl, AlienVault OTX) to find hidden or historical endpoints.
*   **Resilient TLS Probing:** Custom SSL wrappers automatically downgrade or bypass strict TLS requirements, ensuring the scanner successfully connects to legacy or hardened targets without throwing `UNEXPECTED_EOF` errors.
*   **Smart Soft-404 Filter:** Uses blazingly fast `xxhash` body hashing to automatically detect "Catch-All" servers, eliminating false positives caused by generic 200 OK or 302 redirects.
*   **JS Secret Harvester:** Extracts JavaScript files from live pages and scans them against 30+ regex patterns to catch exposed AWS keys, Stripe tokens, JWTs, and internal API endpoints.
*   **Actionable Remediation Engine:** Doesn't just tell you what's broken. Every finding in the report includes a `[FIX]` instruction detailing exactly how to remediate the vulnerability.
*   **Stateful Scan Diffing:** Powered by an asynchronous SQLite persistence layer (`sitemap_guard_v4.db`), the scanner tracks changes over time, highlighting `[+] New Vulnerabilities` or `[✓] Fixed Vulnerabilities` between runs.
*   **Modular Plugin System:** Easily extend the scanner's capabilities by dropping new Python scripts into the `plugins/` folder (e.g., Open Redirects, Advanced CORS).

---

## 🏗️ How the Pipeline Flows

When you initiate a scan, the `BugBountyPipeline` orchestrates the following flow:

1.  **DNS & Passive Reconnaissance:** Queries global DNS servers to map the infrastructure (A, MX, NS records, Subdomains) while concurrently pulling historical URLs from free archives (Wayback, CommonCrawl).
2.  **Tech Fingerprinting & Active Discovery:** Hits the root URL to identify the underlying technology (e.g., WordPress, LiteSpeed, PHP). Based on the detected tech, it injects highly specific paths (like `wp-config.php.bak` or `/.env`) into the active discovery queue.
3.  **Resilient Probing:** Attempts to visit every discovered URL. It automatically filters out Soft-404s (fake "live" pages) and unreachable endpoints, passing only genuinely live targets to the next stage.
4.  **Deep Scanning:**
    *   **Header Scanner:** Checks for missing security headers (HSTS, CSP, etc.).
    *   **JS Scanner:** Parses live HTML, fetches all linked `.js` files, and hunts for secrets.
    *   **Plugins:** Runs custom modules like CORS or Open Redirect checkers.
    *   **Threat Feeds:** Cross-references the URLs against offline Bloom filters populated by OSINT threat feeds.
5.  **Diffing & Reporting:** Saves the results to the SQLite database, calculates the difference from the last scan, and outputs a highly readable `scan_report.txt` and a programmatic `full_results.json`.

---

## 📂 Architecture & Component Breakdown

The codebase is highly modular, separating orchestration, scanning, and utilities.

```text
sitemap_guard/
├── cli.py                    # The Command Line Interface and rich TXT reporting engine.
├── pipeline.py               # The Core Orchestrator. Wires all components and dictates the scan flow.
├── config.py                 # Pydantic-based configuration management (.env support).
├── api.py                    # FastAPI backend for programmatic execution.
│
├── scanner/
│   └── headers.py            # Analyzes HTTP responses for missing/misconfigured security headers.
│
├── plugins/                  # 🔌 Extensible Plugin System
│   ├── __init__.py           # Dynamic plugin loader (auto-discovers GuardPlugin subclasses).
│   ├── base.py               # The GuardPlugin base class.
│   ├── cors_advanced.py      # Plugin: Tests for permissive CORS origins (null, evil.com).
│   └── open_redirect.py      # Plugin: Detects unsafe Location header redirects.
│
├── storage/                  # 💾 Persistence Layer
│   └── db.py                 # Async SQLite engine. Saves scans and calculates Diff logic.
│
└── utils/                    # 🛠️ Core Utilities & Engines
    ├── dns_recon.py          # Extracts A, AAAA, MX, NS, DMARC, and enumerates subdomains.
    ├── fingerprint.py        # Identifies Servers, CMS, Frameworks, and Analytics from headers/body.
    ├── js_scanner.py         # The Regex engine that harvests secrets from Javascript files.
    ├── passive_recon.py      # Queries Wayback Machine, CommonCrawl, and OTX for historical URLs.
    ├── probe.py              # The HTTP request engine. Features legacy TLS fallback and Soft-404 filtering.
    ├── remediations.py       # Maps vulnerability names to human-readable FIX instructions.
    └── threat_feeds.py       # Offline Bloom filter checking against known malicious URL lists.
```

### Deep Dive into Key Files

#### `pipeline.py`
The absolute heart of the project. The `BugBountyPipeline` class manages the concurrency limits via `asyncio`. It handles the failovers (e.g., if a high-speed binary like `httpx` fails, it falls back to our custom `fallback_probe` in `probe.py`). It is responsible for mixing the "Tech-Aware Wordlists" dynamically.

#### `utils/probe.py`
One of the most complex utilities. It solves two major industry problems:
1.  **Strict TLS Servers:** Government or legacy servers often reject modern Python TLS handshakes. This file implements a custom `_LegacySSLAdapter` and falls back to thread-pooled `requests` when `aiohttp` fails.
2.  **Soft-404s:** It implements a "Canary" system. Before scanning, it requests `/sitemap_guard_canary_random123`, takes an `xxhash` of the response, and uses that baseline to filter out "fake" 200 OK responses.

#### `utils/remediations.py`
A simple but highly effective dictionary mapping. Instead of just dumping "Missing HSTS" into a report, `cli.py` queries this module to append precise mitigation instructions (e.g., "Add the Strict-Transport-Security header to your web server config").

#### `storage/db.py`
Powered by `aiosqlite`. It maintains a local `sitemap_guard_v4.db`. When `get_diff()` is called, it performs set mathematics between the current findings and the previous `scan_id` to identify newly introduced vulnerabilities or recently fixed issues.

---

## 🛠️ Usage

**Run a complete scan against a target:**
```bash
python -m sitemap_guard.cli scan https://example.com/
```

**Results are saved in the `./reports/` directory:**
*   `scan_report.txt`: A highly readable, human-friendly security report.
*   `full_results.json`: A machine-readable dump for integration into other CI/CD pipelines.
