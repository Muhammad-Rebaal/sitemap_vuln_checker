"""
Main pipeline orchestrator.

Coordinates: crawl → scan → report with progress tracking,
event loop acceleration (winloop/uvloop), and database persistence.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import structlog
from rich.console import Console
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from sitemap_guard.config import Settings
from sitemap_guard.crawler.engine import CrawlerEngine
from sitemap_guard.crawler.sitemap_gen import generate_sitemap_json, generate_sitemap_xml
from sitemap_guard.models import SiteReport
from sitemap_guard.reporter.engine import ReporterEngine
from sitemap_guard.scanner.engine import ScannerEngine
from sitemap_guard.storage.database import Database
from sitemap_guard.utils.url_utils import extract_domain

logger = structlog.get_logger()
console = Console()


def _install_fast_event_loop() -> None:
    """Install the fastest available event loop for the platform."""
    if sys.platform == "win32":
        try:
            import winloop
            winloop.install()
            logger.info("event_loop.winloop_installed")
            return
        except ImportError:
            logger.debug("winloop not available, using default event loop")
    else:
        try:
            import uvloop
            uvloop.install()
            logger.info("event_loop.uvloop_installed")
            return
        except ImportError:
            logger.debug("uvloop not available, using default event loop")


class Orchestrator:
    """Main pipeline: crawl → scan → report."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.db = Database(settings.database_path)

    def run_full_scan(self) -> SiteReport:
        """Run the complete crawl + scan + report pipeline."""
        _install_fast_event_loop()
        return asyncio.run(self._async_full_scan())

    def run_crawl_only(self) -> list:
        """Run crawl only, generate sitemap."""
        _install_fast_event_loop()
        return asyncio.run(self._async_crawl_only())

    async def _async_full_scan(self) -> SiteReport:
        """Async implementation of the full scan pipeline."""
        total_start = time.monotonic()

        domain = extract_domain(self.settings.target_url)
        report = SiteReport(target_url=self.settings.target_url, domain=domain)

        # Connect database
        await self.db.connect()
        session_id = await self.db.create_session(
            self.settings.target_url, domain,
            str(self.settings.model_dump()),
        )

        try:
            # ── Phase 1: Crawl ────────────────────────────────────
            console.print(f"\n[bold cyan]🕷️  Phase 1: Crawling[/] [dim]{self.settings.target_url}[/]")
            crawler = CrawlerEngine(self.settings)

            progress = Progress(
                SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                BarColumn(), TextColumn("[cyan]{task.completed} URLs"),
                TimeElapsedColumn(), console=console,
            )

            crawl_task_id = progress.add_task("Crawling...", total=None)

            def crawl_progress(count, queue_size, url):
                progress.update(crawl_task_id, completed=count,
                                description=f"Depth scan: {url[:60]}...")

            crawler.on_progress(crawl_progress)

            crawl_start = time.monotonic()
            with progress:
                crawled_urls = await crawler.crawl()
            crawl_duration = time.monotonic() - crawl_start

            report.crawled_urls = crawled_urls
            report.total_urls_discovered = len(crawled_urls)
            report.crawl_duration_seconds = round(crawl_duration, 2)

            console.print(f"  [green]✓[/] Discovered [bold]{len(crawled_urls)}[/] URLs in [cyan]{crawl_duration:.1f}s[/]")

            # Save crawled URLs
            await self.db.save_crawled_urls(session_id, crawled_urls)

            # Generate sitemap
            output_dir = self.settings.output_dir
            sitemap_xml = generate_sitemap_xml(crawled_urls, output_dir / "sitemap.xml")
            sitemap_json = generate_sitemap_json(crawled_urls, output_dir / "sitemap.json")
            console.print(f"  [green]✓[/] Sitemap saved to [cyan]{sitemap_xml}[/]")

            # ── Phase 2: Scan ─────────────────────────────────────
            console.print(f"\n[bold cyan]🔍 Phase 2: Security Scanning[/] [dim]{len(crawled_urls)} URLs[/]")
            scanner = ScannerEngine(self.settings, crawler)

            scan_progress = Progress(
                SpinnerColumn(), TextColumn("[bold magenta]{task.description}"),
                BarColumn(), TextColumn("[cyan]{task.completed} scanned"),
                TimeElapsedColumn(), console=console,
            )
            scan_task_id = scan_progress.add_task("Scanning...", total=len(crawled_urls))
            scanned_count = 0

            def scan_progress_cb(url, finding_count):
                nonlocal scanned_count
                scanned_count += 1
                scan_progress.update(scan_task_id, completed=scanned_count,
                                     description=f"Analyzing: {url[:50]}...")

            scanner.on_progress(scan_progress_cb)

            scan_start = time.monotonic()
            with scan_progress:
                scan_results = await scanner.scan()
            scan_duration = time.monotonic() - scan_start

            report.scan_results = scan_results
            report.total_urls_scanned = len(scan_results)
            report.scan_duration_seconds = round(scan_duration, 2)

            total_findings = sum(len(r.findings) for r in scan_results)
            console.print(f"  [green]✓[/] Found [bold]{total_findings}[/] findings in [cyan]{scan_duration:.1f}s[/]")

            # Save scan results
            await self.db.save_scan_results(session_id, scan_results)

            # ── Phase 3: Report ───────────────────────────────────
            console.print(f"\n[bold cyan]📊 Phase 3: Generating Reports[/]")
            report.total_duration_seconds = round(time.monotonic() - total_start, 2)
            report.compute_overall_risk()

            reporter = ReporterEngine(self.settings)
            generated = reporter.generate(report)

            for path in generated:
                console.print(f"  [green]✓[/] Report: [cyan]{path}[/]")

            # Complete session
            await self.db.complete_session(
                session_id, len(crawled_urls), total_findings, report.overall_risk_score,
            )

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠ Scan interrupted by user[/]")
        finally:
            await self.db.close()

        return report

    async def _async_crawl_only(self) -> list:
        """Crawl-only mode."""
        console.print(f"\n[bold cyan]🕷️  Crawling[/] [dim]{self.settings.target_url}[/]")

        crawler = CrawlerEngine(self.settings)

        progress = Progress(
            SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
            BarColumn(), TextColumn("[cyan]{task.completed} URLs"),
            TimeElapsedColumn(), console=console,
        )
        task_id = progress.add_task("Crawling...", total=None)

        def on_progress(count, queue_size, url):
            progress.update(task_id, completed=count)

        crawler.on_progress(on_progress)

        start = time.monotonic()
        with progress:
            crawled = await crawler.crawl()
        duration = time.monotonic() - start

        console.print(f"  [green]✓[/] Found [bold]{len(crawled)}[/] URLs in [cyan]{duration:.1f}s[/]")

        output_dir = self.settings.output_dir
        xml_path = generate_sitemap_xml(crawled, output_dir / "sitemap.xml")
        json_path = generate_sitemap_json(crawled, output_dir / "sitemap.json")

        console.print(f"  [green]✓[/] XML sitemap: [cyan]{xml_path}[/]")
        console.print(f"  [green]✓[/] JSON sitemap: [cyan]{json_path}[/]")

        return crawled
