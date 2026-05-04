"""
SQLite Async Persistence and Diff Engine — MOD 05
Stores scan results and compares them to previous scans to identify
new URLs, missing URLs, and new findings.
"""
import os
import structlog
from typing import Dict, List, Any
import aiosqlite

logger = structlog.get_logger()

_DB_PATH = "sitemap_guard_v4.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_urls INTEGER,
    total_findings INTEGER
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    url TEXT,
    status INTEGER,
    title TEXT,
    tech TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    finding_type TEXT,
    severity TEXT,
    name TEXT,
    url TEXT,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_urls_scan_id ON urls(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
"""

async def init_db(db_path: str = _DB_PATH):
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


async def save_scan(
    target: str,
    urls: List[Dict],
    findings: List[Dict],
    db_path: str = _DB_PATH
) -> int:
    """Saves a scan and its data. Returns the scan_id."""
    await init_db(db_path)
    
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "INSERT INTO scans (target, total_urls, total_findings) VALUES (?, ?, ?)",
            (target, len(urls), len(findings))
        )
        scan_id = cursor.lastrowid
        if not scan_id:
            scan_id = 0

        # Insert URLs
        url_data = [
            (
                scan_id,
                u.get("url", ""),
                u.get("status", 0),
                u.get("title", ""),
                ",".join(u.get("tech", [])) if isinstance(u.get("tech"), list) else ""
            ) for u in urls
        ]
        await db.executemany(
            "INSERT INTO urls (scan_id, url, status, title, tech) VALUES (?, ?, ?, ?, ?)",
            url_data
        )

        # Insert Findings
        finding_data = []
        for f in findings:
            # Nuclei findings have nested 'info'
            info = f.get("info", {})
            f_type = f.get("type") or info.get("name", "unknown")
            sev = f.get("severity") or info.get("severity", "info")
            name = f.get("name") or info.get("name", "unknown")
            url = f.get("url") or f.get("matched-at", "")
            details = f.get("details") or info.get("description", "")
            finding_data.append((scan_id, f_type, sev, name, url, details))

        await db.executemany(
            "INSERT INTO findings (scan_id, finding_type, severity, name, url, details) VALUES (?, ?, ?, ?, ?, ?)",
            finding_data
        )
        
        await db.commit()
        logger.info("db.saved_scan", scan_id=scan_id, target=target)
        return scan_id


async def get_diff(
    target: str,
    current_urls: List[Dict],
    current_findings: List[Dict],
    db_path: str = _DB_PATH
) -> Dict[str, Any]:
    """
    Compares current scan data against the LAST scan of the same target.
    Returns lists of 'new_urls', 'gone_urls', 'new_findings', 'fixed_findings'.
    """
    if not os.path.exists(db_path):
        return {}

    async with aiosqlite.connect(db_path) as db:
        # Get last scan ID
        cursor = await db.execute(
            "SELECT id FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1 OFFSET 1",
            (target,)
        )
        row = await cursor.fetchone()
        if not row:
            # First time scanning, no diff
            return {}
        
        last_scan_id = row[0]

        # Get old URLs
        cursor = await db.execute("SELECT url FROM urls WHERE scan_id = ?", (last_scan_id,))
        old_urls = {r[0] for r in await cursor.fetchall()}

        # Get old findings
        cursor = await db.execute("SELECT finding_type, url FROM findings WHERE scan_id = ?", (last_scan_id,))
        old_findings = {(r[0], r[1]) for r in await cursor.fetchall()}

    # Calculate diffs
    cur_url_set = {u.get("url", "") for u in current_urls if u.get("url")}
    new_urls = list(cur_url_set - old_urls)
    gone_urls = list(old_urls - cur_url_set)

    cur_finding_set = set()
    for f in current_findings:
        info = f.get("info", {})
        f_type = f.get("type") or info.get("name", "unknown")
        url = f.get("url") or f.get("matched-at", "")
        if f_type and url:
            cur_finding_set.add((f_type, url))

    new_findings = list(cur_finding_set - old_findings)
    fixed_findings = list(old_findings - cur_finding_set)

    diff = {
        "new_urls": new_urls,
        "gone_urls": gone_urls,
        "new_findings": new_findings,
        "fixed_findings": fixed_findings
    }
    
    logger.info("db.diff_calculated", new_urls=len(new_urls), new_findings=len(new_findings))
    return diff
