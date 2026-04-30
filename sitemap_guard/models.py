"""
Data models for the entire application.

Uses dataclasses with orjson serialization and NumPy interop
for Numba-accelerated batch processing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import numpy as np
import orjson


class Severity(str, Enum):
    """Severity levels for scan findings, ordered from most to least critical."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def numeric(self) -> int:
        """Numeric score for severity (higher = more critical). Used by Numba."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @property
    def weight(self) -> float:
        """Weight for risk scoring. Fed to Numba kernels."""
        return {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 15.0,
            Severity.MEDIUM: 8.0,
            Severity.LOW: 3.0,
            Severity.INFO: 0.5,
        }[self]

    @property
    def color(self) -> str:
        """Rich terminal color."""
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "dark_orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]

    @property
    def hex_color(self) -> str:
        """Hex color for HTML reports."""
        return {
            Severity.CRITICAL: "#ff1744",
            Severity.HIGH: "#ff6d00",
            Severity.MEDIUM: "#ffd600",
            Severity.LOW: "#00e5ff",
            Severity.INFO: "#78909c",
        }[self]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CrawledURL:
    """Represents a single URL discovered during crawling."""

    url: str
    status_code: int = 0
    content_type: str = ""
    response_time_ms: float = 0.0
    depth: int = 0
    parent_url: Optional[str] = None
    title: Optional[str] = None
    meta_description: Optional[str] = None
    content_length: int = 0
    redirect_url: Optional[str] = None
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanFinding:
    """A single security finding from an analyzer."""

    analyzer_name: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    reference_url: str = ""
    cwe_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class URLScanResult:
    """Aggregated scan results for a single URL."""

    url: str
    findings: list[ScanFinding] = field(default_factory=list)
    risk_score: float = 0.0
    scan_duration_ms: float = 0.0
    scan_timestamp: str = field(default_factory=_now_iso)
    analyzers_run: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: f.severity.numeric).severity

    def get_severity_weights_array(self) -> np.ndarray:
        """Convert findings to NumPy array of weights for Numba processing."""
        if not self.findings:
            return np.zeros(0, dtype=np.float64)
        return np.array([f.severity.weight for f in self.findings], dtype=np.float64)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "max_severity": self.max_severity.value,
            "finding_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "analyzers_run": self.analyzers_run,
            "scan_duration_ms": self.scan_duration_ms,
            "scan_timestamp": self.scan_timestamp,
        }


@dataclass
class SiteReport:
    """Complete scan report for an entire website."""

    target_url: str
    domain: str
    total_urls_discovered: int = 0
    total_urls_scanned: int = 0
    crawl_duration_seconds: float = 0.0
    scan_duration_seconds: float = 0.0
    total_duration_seconds: float = 0.0
    crawled_urls: list[CrawledURL] = field(default_factory=list)
    scan_results: list[URLScanResult] = field(default_factory=list)
    overall_risk_score: float = 0.0
    timestamp: str = field(default_factory=_now_iso)
    settings_used: dict[str, Any] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.scan_results)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for result in self.scan_results:
            for finding in result.findings:
                counts[finding.severity.value] += 1
        return counts

    @property
    def max_severity(self) -> Severity:
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if self.severity_counts[sev.value] > 0:
                return sev
        return Severity.INFO

    def build_severity_array(self) -> np.ndarray:
        """Build a flat NumPy array of all severity numerics for Numba aggregation."""
        all_sevs = []
        for result in self.scan_results:
            for finding in result.findings:
                all_sevs.append(finding.severity.numeric)
        return np.array(all_sevs, dtype=np.int64) if all_sevs else np.zeros(0, dtype=np.int64)

    def compute_overall_risk(self) -> None:
        """Compute the overall risk score using the Numba engine."""
        from sitemap_guard.utils.scoring import compute_site_risk
        if not self.scan_results:
            self.overall_risk_score = 0.0
            return
        scores = np.array([r.risk_score for r in self.scan_results], dtype=np.float64)
        self.overall_risk_score = round(float(compute_site_risk(scores)), 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "domain": self.domain,
            "total_urls_discovered": self.total_urls_discovered,
            "total_urls_scanned": self.total_urls_scanned,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "overall_risk_score": self.overall_risk_score,
            "max_severity": self.max_severity.value,
            "crawl_duration_seconds": self.crawl_duration_seconds,
            "scan_duration_seconds": self.scan_duration_seconds,
            "total_duration_seconds": self.total_duration_seconds,
            "scan_results": [r.to_dict() for r in self.scan_results],
            "timestamp": self.timestamp,
        }

    def to_json(self) -> bytes:
        """Serialize to JSON bytes using orjson (10x faster)."""
        return orjson.dumps(self.to_dict(), option=orjson.OPT_INDENT_2)

    def to_json_str(self) -> str:
        """Serialize to JSON string using orjson."""
        return self.to_json().decode("utf-8")
