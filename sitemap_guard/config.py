"""
Pydantic-based configuration with environment variable support.

Loads settings from .env file and environment variables.
All settings have sensible defaults — works out of the box.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Target ────────────────────────────────────────────────────────
    target_url: str = ""

    # ── Crawler Settings ──────────────────────────────────────────────
    max_crawl_depth: int = Field(default=3, ge=1, le=50)
    max_concurrent_requests: int = Field(default=50, ge=1, le=500)
    request_timeout: int = Field(default=10, ge=1, le=60)
    respect_robots_txt: bool = True
    user_agent: str = "SiteMapGuard/2.0 (+https://github.com/sitemap-guard; security-scanner)"
    follow_subdomains: bool = False

    # ── Bloom Filter Settings ────────────────────────────────────────
    bloom_filter_capacity: int = Field(default=1_000_000, ge=1000)
    bloom_filter_error_rate: float = Field(default=0.001, gt=0.0, lt=1.0)

    # ── API Keys (Optional — all free tier) ──────────────────────────
    google_safebrowsing_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    # ── Analyzer Toggles ─────────────────────────────────────────────
    enable_ssl_analyzer: bool = True
    enable_headers_analyzer: bool = True
    enable_content_analyzer: bool = True
    enable_dns_analyzer: bool = True
    enable_tech_detector: bool = True
    enable_safebrowsing: bool = False
    enable_virustotal: bool = False
    enable_phishtank: bool = True

    # ── Output Settings ──────────────────────────────────────────────
    output_dir: Path = Field(default_factory=lambda: Path("./reports"))
    report_format: str = Field("html", description="html, json, csv, or all")
    verbose: bool = False
    
    # --- Obscura Headless Browser ---
    use_obscura: bool = Field(True, description="Use Obscura headless browser instead of raw aiohttp")
    obscura_path: str = Field("./bin/obscura.exe", description="Path to the Obscura executable")
    database_path: Path = Path("./sitemap_guard.db")
    
    # ── Threat Feed Settings ─────────────────────────────────────────
    enable_offline_threats: bool = True
    threat_feed_urls: list[str] = [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://openphish.com/feed.txt",
    ]
    threat_feed_cache_dir: Path = Field(default_factory=lambda: Path("./data/threat_feeds"))

    @field_validator("report_format")
    @classmethod
    def validate_report_format(cls, v: str) -> str:
        allowed = {"html", "json", "csv", "terminal", "all"}
        if v.lower() not in allowed:
            raise ValueError(f"report_format must be one of {allowed}")
        return v.lower()

    @field_validator("output_dir", mode="before")
    @classmethod
    def ensure_output_dir(cls, v: str | Path) -> Path:
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_enabled_analyzers(self) -> list[str]:
        """Return list of enabled analyzer names."""
        analyzers = []
        if self.enable_ssl_analyzer:
            analyzers.append("ssl")
        if self.enable_headers_analyzer:
            analyzers.append("headers")
        if self.enable_content_analyzer:
            analyzers.append("content")
        if self.enable_dns_analyzer:
            analyzers.append("dns")
        if self.enable_tech_detector:
            analyzers.append("tech")
        if self.enable_safebrowsing and self.google_safebrowsing_api_key:
            analyzers.append("safebrowsing")
        if self.enable_virustotal and self.virustotal_api_key:
            analyzers.append("virustotal")
        if self.enable_phishtank:
            analyzers.append("phishtank")
        return analyzers


def get_settings(**overrides) -> Settings:
    """Create a Settings instance with optional overrides."""
    return Settings(**overrides)
