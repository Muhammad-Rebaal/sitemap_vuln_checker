"""
SQLite database via aiosqlite for scan persistence.
Enables incremental scanning, historical comparison, and resume.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite
import structlog

from sitemap_guard.models import CrawledURL, ScanFinding, Severity, URLScanResult

logger = structlog.get_logger()

SCHEMA = """
CREATE TABLE IF NOT EXISTS crawl_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    total_urls INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    overall_risk_score REAL DEFAULT 0.0,
    settings_json TEXT
);

CREATE TABLE IF NOT EXISTS discovered_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER DEFAULT 0,
    content_type TEXT DEFAULT '',
    response_time_ms REAL DEFAULT 0.0,
    depth INTEGER DEFAULT 0,
    parent_url TEXT,
    title TEXT,
    content_length INTEGER DEFAULT 0,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES crawl_sessions(id)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    risk_score REAL DEFAULT 0.0,
    finding_count INTEGER DEFAULT 0,
    scan_duration_ms REAL DEFAULT 0.0,
    scan_timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES crawl_sessions(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER NOT NULL,
    analyzer_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    reference_url TEXT,
    cwe_id TEXT,
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id)
);

CREATE INDEX IF NOT EXISTS idx_urls_session ON discovered_urls(session_id);
CREATE INDEX IF NOT EXISTS idx_results_session ON scan_results(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_result ON findings(scan_result_id);
"""


class Database:
    """Async SQLite database for scan persistence."""

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.db_path))
        await self._db.executescript(SCHEMA)
        await self._db.commit()
        logger.debug("database.connected", path=str(self.db_path))

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    async def create_session(self, target_url: str, domain: str, settings_json: str = "") -> int:
        assert self._db is not None
        cursor = await self._db.execute(
            "INSERT INTO crawl_sessions (target_url, domain, started_at, settings_json) VALUES (?, ?, ?, ?)",
            (target_url, domain, datetime.now(timezone.utc).isoformat(), settings_json),
        )
        await self._db.commit()
        return cursor.lastrowid or 0

    async def complete_session(
        self, session_id: int, total_urls: int, total_findings: int, risk_score: float,
    ) -> None:
        assert self._db is not None
        await self._db.execute(
            "UPDATE crawl_sessions SET completed_at=?, total_urls=?, total_findings=?, overall_risk_score=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), total_urls, total_findings, risk_score, session_id),
        )
        await self._db.commit()

    async def save_crawled_urls(self, session_id: int, urls: list[CrawledURL]) -> None:
        assert self._db is not None
        rows = [
            (session_id, u.url, u.status_code, u.content_type, u.response_time_ms,
             u.depth, u.parent_url, u.title, u.content_length, u.timestamp)
            for u in urls
        ]
        await self._db.executemany(
            "INSERT INTO discovered_urls (session_id, url, status_code, content_type, response_time_ms, depth, parent_url, title, content_length, timestamp) VALUES (?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        await self._db.commit()

    async def save_scan_results(self, session_id: int, results: list[URLScanResult]) -> None:
        assert self._db is not None
        for result in results:
            cursor = await self._db.execute(
                "INSERT INTO scan_results (session_id, url, risk_score, finding_count, scan_duration_ms, scan_timestamp) VALUES (?,?,?,?,?,?)",
                (session_id, result.url, result.risk_score, len(result.findings),
                 result.scan_duration_ms, result.scan_timestamp),
            )
            result_id = cursor.lastrowid or 0

            if result.findings:
                finding_rows = [
                    (result_id, f.analyzer_name, f.severity.value, f.title,
                     f.description, f.evidence, f.remediation, f.reference_url, f.cwe_id)
                    for f in result.findings
                ]
                await self._db.executemany(
                    "INSERT INTO findings (scan_result_id, analyzer_name, severity, title, description, evidence, remediation, reference_url, cwe_id) VALUES (?,?,?,?,?,?,?,?,?)",
                    finding_rows,
                )
        await self._db.commit()

    async def get_session_history(self, domain: str, limit: int = 10) -> list[dict]:
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT id, target_url, started_at, completed_at, total_urls, total_findings, overall_risk_score FROM crawl_sessions WHERE domain=? ORDER BY started_at DESC LIMIT ?",
            (domain, limit),
        )
        rows = await cursor.fetchall()
        return [
            {"id": r[0], "target_url": r[1], "started_at": r[2], "completed_at": r[3],
             "total_urls": r[4], "total_findings": r[5], "risk_score": r[6]}
            for r in rows
        ]
