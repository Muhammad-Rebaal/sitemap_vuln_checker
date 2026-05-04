# SiteMap Guard v4.0: Deep Analysis & Modification Roadmap

This document outlines the strategic gap analysis of **SiteMap Guard v3** and provides a technical blueprint for evolving it into a world-class security intelligence platform.

---

## 1. Executive Summary: Current State
**SiteMap Guard v3** is currently an **Active Probing Utility**. It is excellent at connectivity (SSL bypass) and basic DNS reconnaissance. However, in the 2024 security landscape, "Active Probing" is often blocked by WAFs (Cloudflare/Akamai) or missed by automated internal security teams.

### Current Strengths:
- **Resiliency:** Unmatched ability to handle broken TLS/SSL (Legacy context).
- **DNS Visibility:** Good integration of A, MX, and Subdomain data.
- **Orchestration:** Successfully combines Nuclei and Path Probing.

---

## 2. Competitive Gap Analysis
How SiteMap Guard compares to the "Pro" stack (Burp Suite, ReconFTW, Caido):

| Feature | SiteMap Guard v3 | Industry Standard (2024) | Gap Severity |
| :--- | :--- | :--- | :--- |
| **Data Source** | Live Server Only | **Passive + Active** (Wayback, OTX, GitHub) | 🔴 CRITICAL |
| **Response Analysis** | Status Code (200/302) | **Content Fingerprinting** (Fuzzy hashing) | 🟠 MAJOR |
| **JS Analysis** | None (Static links only) | **Secret Harvesting** (Regex for AWS/API Keys) | 🔴 CRITICAL |
| **Path Probing** | Static List (80 paths) | **Technology-Aware Wordlists** | 🟠 MAJOR |
| **WAF Evasion** | None | **Jitter, Header Spoofing, Proxy Rotation** | 🟡 MINOR |

---

## 3. The "Missing" Features (Unable to do currently)

### A. Passive Discovery Integration
Professional scanners use "Passive Recon" to find URLs that *used* to exist. Developers often delete links from the sitemap but forget to delete the files from the server.
*   **The Modification:** Integrate APIs for `Wayback Machine`, `Common Crawl`, and `AlienVault OTX`.

### B. "Soft-404" & Redirect Intelligence
Your current version reports `302 Redirects` as findings. On many sites, this results in 100% false positives.
*   **The Modification:** Implement a **Baseline Comparator**. Request a non-existent URL (e.g., `/random_123`) first. If `/admin` looks exactly like `/random_123`, discard it.

### C. JavaScript (JS) Secret Harvester
Modern sitemaps often link to large `.js` files. These files frequently contain hardcoded API keys, Firebase URLs, or internal dev endpoints.
*   **The Modification:** Add a JS-parser that runs Regex patterns against every discovered `.js` file to find "Leaky Secrets."

---

## 4. Technical Roadmap for v4.0 (Modifications)

### [MOD 01] Passive URL Aggregator
*   **File:** `sitemap_guard/utils/passive_recon.py` [NEW]
*   **Logic:** Query `https://web.archive.org/cdx/search/xd?url=*.target.com` to find historical sitemaps. Merge these with your active discovery list.

### [MOD 02] Smart Response Filter
*   **File:** `sitemap_guard/utils/probe.py` [UPDATE]
*   **Logic:** 
    ```python
    baseline = await get_response(target + "/non_existent_path_xyz")
    if current_response.body_hash == baseline.body_hash:
        return IGNORE
    ```

### [MOD 03] Technology-Aware Wordlists
*   **File:** `sitemap_guard/pipeline.py` [UPDATE]
*   **Logic:** Use the `Tech` detected in DNS/Probe to select wordlists.
    - If `CMS == WordPress` -> Add `wp-config.php.bak`, `wp-content/debug.log`.
    - If `Server == IIS` -> Add `web.config`, `Trace.axd`.

### [MOD 04] Remediation Reporting
*   **File:** `sitemap_guard/cli.py` [UPDATE]
*   **Logic:** Don't just report "Missing HSTS." Add a "How to Fix" section:
    - *Fix:* "Add 'Strict-Transport-Security: max-age=31536000' to your Nginx/Apache config."

---

## 5. Architectural Improvements
1.  **Persistence Layer:** Move from `full_results.json` to a local **SQLite database**. This allows you to track "Diffs" (e.g., "What changed in the sitemap since my last scan yesterday?").
2.  **Plugin System:** Allow users to add their own "Guard" scripts in Python without editing the core `pipeline.py`.

---

## 6. Immediate "Quick Fixes" for your next run:
1.  **Filter 302s:** In `cli.py`, hide status codes `301/302` unless they redirect to a *different* domain (potential open redirect).
2.  **Expand Paths:** Increase `COMMON_PATHS` from 80 to 250+ using a standard SecLists wordlist.

---
*Analysis generated on 2026-05-04 by Antigravity AI.*
