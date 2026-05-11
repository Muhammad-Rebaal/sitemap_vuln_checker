# SiteMap Guard

SiteMap Guard is an autonomous sitemap discovery and web security scanning toolkit. It combines multiple open-source scanners and custom analyzers to discover pages, probe HTTP endpoints resiliently (including legacy TLS servers), and run lightweight security checks — producing human-readable reports (plain-text, JSON, HTML) and an API/streamlit dashboard for interaction.

---

## Highlights / What it does

- Crawl and discover same-host URLs (robots, sitemaps, BFS HTML crawl, common paths, optional JS crawler)
- Resilient HTTP probing with aiohttp + legacy-SSL fallbacks and a requests-based thread fallback
- Fingerprints server / tech stack, extracts titles, and detects redirects
- Runs template-driven scanners (Nuclei) and offline threat feeds
- Scans JavaScript bundles for embedded secrets (JS harvester)
- Produces enhanced plain-text reports (Enhanced Sitemap Vulnerability Report), JSON, CSV, and a Streamlit dashboard + FastAPI

---

## Main entry points

- `python -m sitemap_guard` — primary CLI entry. Subcommands:
  - `scan <url>` — run the full pipeline (discovery, probe, nuclei, JS harvest, report)
  - `sitemap <url>` — run enhanced sitemap discovery + probe + plain-text report
  - `serve` — start the FastAPI backend (used by the Streamlit UI)

- `app.py` — Streamlit dashboard that talks to the FastAPI backend (`http://localhost:8000` by default).

Note: `sitemap_guard/__main__.py` simply calls the CLI, so `python -m sitemap_guard` is the recommended invocation.

---

## Dependencies

Primary Python packages the project uses (non-exhaustive):

- Python 3.10+ recommended
- aiohttp — async HTTP client
- requests — synchronous HTTP fallback
- structlog — structured logging
- pydantic / pydantic-settings — configuration handling
- fastapi, uvicorn — API server
- rich — CLI progress & pretty output
- xxhash — fast hashing of HTML bodies
- usp — sitemap parsing helper
- streamlit, pandas — optional UI dashboard components

Optional external binaries (improve discovery/scanning capabilities):

- httpx (binary) — fast mass HTTP probing (project uses PD httpx if available)
- nuclei — template-driven vulnerability scanner
- ffuf — fuzzing / discovery
- katana — headless JS-enabled crawler (optional)
- obscura / headless browser — optional headless browsing for JS-heavy sites

You can run the scanner without the binaries (the Python fallbacks will be used) but some features may be slower or less capable.

---

## Quick start (install & run)

1. Clone repository:

```bash
git clone <repo-url> .
cd SiteMap
```

2. Create a virtualenv and install dependencies:

```bash
python -m venv .venv
# Activate the venv (Windows)
.venv\\Scripts\\activate
# Or (Unix/mac)
source .venv/bin/activate

pip install -r requirements.txt
```

If `requirements.txt` isn't provided, install the primary deps:

```bash
pip install aiohttp requests structlog pydantic pydantic-settings fastapi uvicorn rich xxhash usp streamlit pandas
```

3. (Optional) Place optional binaries in `bin/`:

- `bin/httpx` or `bin/httpx.exe`
- `bin/nuclei` or `bin/nuclei.exe`
- `bin/ffuf`, `bin/katana`, `bin/obscura` as needed

4. Run the CLI:

- Full pipeline (crawl + full scan + report):

```bash
python -m sitemap_guard scan https://example.com --output ./reports
```

- Generate enhanced sitemap report only:

```bash
python -m sitemap_guard sitemap example.com --max-urls 100
```

- Start API server (for Streamlit UI / remote requests):

```bash
python -m sitemap_guard serve --host 0.0.0.0 --port 8000
# or using uvicorn directly:
uvicorn sitemap_guard.api:app --host 0.0.0.0 --port 8000
```

5. Start the Streamlit dashboard (optional):

```bash
streamlit run app.py
# The Streamlit UI calls the FastAPI /scan endpoint by default at http://localhost:8000
```

---

## Configuration & environment

- All runtime options are managed via `sitemap_guard.config.Settings` (pydantic). It supports a `.env` file and environment variables.
- Key settings: `target_url`, `max_crawl_depth`, `max_concurrent_requests`, `request_timeout`, `user_agent`, `output_dir`, `report_format`.
- Optional API keys (set in environment or .env): `GOOGLE_SAFEBROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`.

Example `.env`:

```text
TARGET_URL=https://example.com
MAX_CRAWL_DEPTH=3
REQUEST_TIMEOUT=12
OUTPUT_DIR=./reports
# optional
GOOGLE_SAFEBROWSING_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

---

## User flow (how a typical scan runs)

1. User invokes the CLI `scan` or the API `/scan`.
2. Pipeline starts:
   - DNS & passive recon tasks are launched.
   - Discovery: robots.txt, direct sitemap fetch, USP sitemap parsing, common path probing, optional Katana JS crawl.
   - URLs are filtered and deduplicated.
   - HTTP probing: tries PD `httpx` binary if available; falls back to Python `fallback_probe` (aiohttp + requests fallback). The probing includes legacy TLS options and threaded DNS resolver to increase reliability.
   - Scannable live targets are enriched (headers, titles, tech).
   - Header scanning + Nuclei templates + offline threat feeds + JS secret harvesting are run.
   - Findings are combined and persisted (SQLite DB path configurable).
   - Reporter(s) generate outputs: enhanced plain-text report, JSON, CSV, and other formats depending on settings.
3. Results are returned to the CLI or API, and reports saved to `./reports/`.
4. Streamlit UI polls the API for task status and displays results in a dashboard.

---

## File / Directory map (high level)

Root
- app.py — Streamlit dashboard UI (calls FastAPI `/scan` + `/status`).
- requirements.txt — (expected) pinned Python dependencies (create if missing).
- README.md — this file.
- reports/ — default output directory with generated reports (.txt, .json).

sitemap_guard/ (main package)
- __main__.py — entrypoint that calls the CLI.
- cli.py — Click-based command-line interface and reporting glue.
- config.py — pydantic Settings class (.env + env var support).
- pipeline.py — BugBountyPipeline orchestrating discovery → probe → scan → report.
- api.py — FastAPI server exposing `/scan` and `/status` endpoints (in-memory task store).
- reporter/
  - enhanced_sitemap_report.py — Enhanced plain-text report generator (report layout & probe orchestration for reporting).
  - json_report.py, csv_report.py, html_report.py, terminal_report.py — other report formats.
- scanner/
  - engine.py — asynchronous scanner engine, probing logic, tech fingerprinting, requests fallback.
  - headers.py — header-based security checks (HeaderScanner).
- crawler/
  - engine.py, sitemap_gen.py, link_extractor.py — discovery and BFS crawling logic.
- storage/
  - database.py, db.py — persistence helpers & session storage.
- utils/
  - probe.py — resilient probing helper used by pipeline (aiohttp + requests fallbacks).
  - dns_recon.py, passive_recon.py, js_scanner.py, threat_feeds.py — recon and scanning helpers.
  - rate_limiter.py, url_utils.py, fingerprint.py, bloom.py, remediations.py, auto_fixer.py — misc utilities.
- plugins/ — plugin-based checks (CORS, open-redirects, etc.).
- models.py — typed dataclasses / pydantic models used across the pipeline.
- orchestrator.py — higher-level run orchestration (used by CLI / API).

Other
- bin/ — expected location for optional external binaries (httpx, nuclei, ffuf, katana, obscura).
- data/ — caches (threat feed caches, etc.)

---

## Notes on important internals

- Resilient SSL handling: multiple places create SSL contexts that disable cert verification and enable legacy server connect (OP_LEGACY_SERVER_CONNECT) and set ciphers `ALL:@SECLEVEL=0` to accommodate older TLS servers.
- DNS reliability: the reporter sets a `ThreadedResolver` with `aiohttp` to use the system resolver (avoids issues with async resolver on some Windows setups). It also forces IPv4 in some places to avoid IPv6-only resolver issues.
- Probing fallback: primary probing uses PD httpx binary (if present) for performance. When missing or when httpx returns no results, the pipeline falls back to `fallback_probe` (aiohttp + requests-based fallback in threads).
- Reports: `enhanced_sitemap_report.py` implements the plain-text "Enhanced Sitemap Vulnerability Report" layout used in the `reports/` directory.

---

## Running examples

- Full scan output to reports:
```bash
python -m sitemap_guard scan https://burhanbaig.com --output ./reports
```

- Generate only sitemap/probe report (plain-text):
```bash
python -m sitemap_guard sitemap burhanbaig.com --max-urls 100
# Output: reports/burhanbaig.com_report_<timestamp>.txt
```

- Start API + Streamlit UI:
```bash
python -m sitemap_guard serve --port 8000
streamlit run app.py
```

Then open the Streamlit UI and enter a target; it will POST to `/scan`, poll `/status/{task_id}`, and show results.

---

## Extending the project

- Add more analyzers under `sitemap_guard/scanner/analyzers/` and register them in `ScannerEngine._register_analyzers`.
- Add or update Nuclei templates and place the `nuclei` binary in `bin/` for template-based scans.
- Implement persistent task storage for the API instead of the in-memory `tasks_store`.

---

## Troubleshooting

- If you get "connection_error" for every URL:
  - Check network / firewall / VPN settings.
  - Verify DNS resolution (`nslookup example.com`).
  - Ensure `ThreadedResolver` is enabled (reporter uses it) and/or try forcing IPv4.

- If Nuclei / httpx features don't run, ensure binaries exist in `bin/` or install them system-wide.

---

If you want, I can:
- Generate a pinned `requirements.txt` from your environment,
- Create a sample `.env` file,
- Add CONTRIBUTING.md and docs for adding new analyzers.

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
