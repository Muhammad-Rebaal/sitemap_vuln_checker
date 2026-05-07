import asyncio
import click
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import uvicorn
import sys

from sitemap_guard.pipeline import BugBountyPipeline
from sitemap_guard.reporter.enhanced_sitemap_report import EnhancedSitemapReporter

console = Console()

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# TXT Report generator
# ─────────────────────────────────────────────────────────────────────────────

def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev.lower(), 5)


def generate_txt_report(results: dict, output_path: str) -> None:
    """Write a structured plain-text scan report."""
    target = results.get("target", "")
    live_targets = results.get("live_targets", [])
    dns_info = results.get("dns_info", {})
    header_findings = results.get("header_findings", [])
    nuclei_findings = results.get("nuclei_findings", [])
    threat_findings = results.get("threat_findings", [])
    js_secrets = results.get("js_secrets", [])
    plugin_findings = results.get("plugin_findings", [])
    diff = results.get("diff", {})
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    from sitemap_guard.utils.remediations import get_remediation

    # Separate real findings from connection errors
    real_header = [f for f in header_findings if f.get("type") != "connection_error"]
    real_live = [t for t in live_targets if t.get("status", 0) not in (0,)]

    lines = []
    SEP = "=" * 78
    SEP2 = "-" * 78

    def section(title: str):
        lines.append("")
        lines.append(SEP)
        lines.append(f"  {title}")
        lines.append(SEP)

    def sub(title: str):
        lines.append("")
        lines.append(f"  {title}")
        lines.append("  " + SEP2[:74])

    # ── Header ────────────────────────────────────────────────────────────────
    lines.append(SEP)
    lines.append("  SITEMAP GUARD v3 — SECURITY SCAN REPORT")
    lines.append(SEP)
    lines.append(f"  Target   : {target}")
    lines.append(f"  Scanned  : {ts}")
    lines.append(f"  Live URLs: {len(real_live)} confirmed  |  {len(live_targets)} discovered")
    lines.append(f"  Findings : {len(real_header)} hdr | {len(nuclei_findings)} nuclei | {len(threat_findings)} threat | {len(js_secrets)} JS | {len(plugin_findings)} plug")
    lines.append(SEP)

    # ── DNS Recon ─────────────────────────────────────────────────────────────
    if dns_info:
        section("1. DNS RECONNAISSANCE")
        domain = dns_info.get("domain", "")
        lines.append(f"  Domain          : {domain}")

        a = dns_info.get("a_records", [])
        if a:
            lines.append(f"  A Records       : {', '.join(a)}")

        aaaa = dns_info.get("aaaa_records", [])
        if aaaa:
            lines.append(f"  AAAA Records    : {', '.join(aaaa)}")

        ns = dns_info.get("ns_records", [])
        if ns:
            lines.append(f"  NS Records      : {', '.join(ns)}")

        mx = dns_info.get("mx_records", [])
        if mx:
            mx_str = ", ".join(f"{m['preference']} {m['exchange']}" for m in mx)
            lines.append(f"  MX Records      : {mx_str}")

        if dns_info.get("spf"):
            lines.append(f"  SPF             : {dns_info['spf']}")
        if dns_info.get("dmarc"):
            lines.append(f"  DMARC           : {dns_info['dmarc']}")
        if dns_info.get("cdn"):
            lines.append(f"  CDN             : {dns_info['cdn']}")
        if dns_info.get("email_provider"):
            lines.append(f"  Email Provider  : {dns_info['email_provider']}")

        subs = dns_info.get("live_subdomains", [])
        if subs:
            lines.append(f"  Live Subdomains : {len(subs)} found")
            for s in subs:
                lines.append(f"    • {s['subdomain']}  ->  {', '.join(s['ips'])}")

    # ── Live Hosts ────────────────────────────────────────────────────────────
    section("2. LIVE HOST DISCOVERY")
    lines.append(f"  Total discovered : {len(live_targets)}")
    lines.append(f"  Confirmed live   : {len(real_live)}")
    lines.append("")

    if real_live:
        sub("Confirmed Live URLs")
        for t in real_live:
            tech = ", ".join(t.get("tech", [])[:5])
            title = (t.get("title") or "")[:50]
            lines.append(f"  [{t.get('status')}]  {t.get('url', '')}")
            if title:
                lines.append(f"         Title : {title}")
            if tech:
                lines.append(f"         Tech  : {tech}")

    sub("All Discovered URLs (including unreachable)")
    for t in live_targets:
        status = t.get("status", 0)
        tag = f"[{status}]" if status else "[---]"
        lines.append(f"  {tag}  {t.get('url', '')}")

    # ── Security Header Findings ──────────────────────────────────────────────
    section("3. SECURITY HEADER ANALYSIS")
    if real_header:
        # Deduplicate by (type, name), sorted by severity
        seen: dict = {}
        for f in real_header:
            key = (f.get("type"), f.get("name"))
            seen.setdefault(key, {"f": f, "count": 0, "urls": []})
            seen[key]["count"] += 1
            if len(seen[key]["urls"]) < 3:
                seen[key]["urls"].append(f.get("url", ""))

        sorted_findings = sorted(seen.values(), key=lambda x: _severity_rank(x["f"].get("severity", "info")))

        for item in sorted_findings:
            f = item["f"]
            sev = f.get("severity", "info").upper()
            name = f.get("name", "")
            count = item["count"]
            lines.append(f"  [{sev}]  {name}  (affected: {count} URL(s))")
            for u in item["urls"]:
                lines.append(f"          -> {u}")
            if f.get("details"):
                lines.append(f"          Detail: {f['details']}")
            _, fix = get_remediation(name, f.get("type", ""))
            lines.append(f"          [FIX] : {fix}")
    else:
        lines.append("  No security header findings detected.")

    # ── Nuclei Findings ───────────────────────────────────────────────────────
    section("4. NUCLEI VULNERABILITY SCAN")
    if nuclei_findings:
        sorted_nuc = sorted(nuclei_findings,
                            key=lambda x: _severity_rank(x.get("info", {}).get("severity", "info")))
        for f in sorted_nuc:
            info = f.get("info", {})
            sev = info.get("severity", "unknown").upper()
            name = info.get("name", "unknown")
            url = f.get("url", f.get("matched-at", ""))
            tags = ", ".join(info.get("tags", [])[:4])
            lines.append(f"  [{sev}]  {name}")
            lines.append(f"          URL   : {url}")
            if tags:
                lines.append(f"          Tags  : {tags}")
            desc = (info.get("description") or "")[:120]
            if desc:
                lines.append(f"          Desc  : {desc}")
            _, fix = get_remediation(name, "nuclei")
            lines.append(f"          [FIX] : {fix}")
            lines.append("")
    else:
        lines.append("  No Nuclei findings detected.")

    # ── Threat Feed Findings ──────────────────────────────────────────────────
    if threat_findings:
        section("5. THREAT FEED MATCHES")
        for f in threat_findings:
            lines.append(f"  [{f.get('severity','high').upper()}]  {f.get('type','malicious')}  ->  {f.get('url','')}")

    # ── JS Secrets ────────────────────────────────────────────────────────────
    if js_secrets:
        section("6. JAVASCRIPT SECRETS")
        for f in js_secrets:
            lines.append(f"  [{f.get('severity','high').upper()}]  {f.get('name','Secret')}  ->  {f.get('url','')}")
            if f.get("details"):
                lines.append(f"          Detail: {f['details']}")
            _, fix = get_remediation(f.get("name", ""), f.get("type", ""))
            lines.append(f"          [FIX] : {fix}")
            lines.append("")

    # ── Plugin Findings ───────────────────────────────────────────────────────
    if plugin_findings:
        section("7. PLUGIN FINDINGS")
        for f in plugin_findings:
            lines.append(f"  [{f.get('severity','info').upper()}]  {f.get('name','Plugin Finding')}  ->  {f.get('url','')}")
            if f.get("details"):
                lines.append(f"          Detail: {f['details']}")
            _, fix = get_remediation(f.get("name", ""), f.get("type", ""))
            lines.append(f"          [FIX] : {fix}")

    # ── Scan Diff ─────────────────────────────────────────────────────────────
    if diff:
        section("8. SCAN DIFF (CHANGES SINCE LAST SCAN)")
        if diff.get("new_urls"):
            lines.append(f"  [+] New URLs Discovered : {len(diff['new_urls'])}")
        if diff.get("gone_urls"):
            lines.append(f"  [-] URLs Gone           : {len(diff['gone_urls'])}")
        if diff.get("new_findings"):
            lines.append(f"  [!] New Vulnerabilities : {len(diff['new_findings'])}")
        if diff.get("fixed_findings"):
            lines.append(f"  [✓] Fixed Vulnerabilities: {len(diff['fixed_findings'])}")
        if not any(diff.values()):
            lines.append("  No changes detected since last scan.")

    # ── Summary ───────────────────────────────────────────────────────────────
    section("SUMMARY")
    total = len(real_header) + len(nuclei_findings) + len(threat_findings) + len(js_secrets) + len(plugin_findings)
    lines.append(f"  Subdomains found        : {len(dns_info.get('live_subdomains', []))}")
    lines.append(f"  Live hosts (real)       : {len(real_live)}")
    lines.append(f"  Header / security issues: {len(real_header)}")
    lines.append(f"  Nuclei findings         : {len(nuclei_findings)}")
    lines.append(f"  Threat feed matches     : {len(threat_findings)}")
    lines.append(f"  Total findings          : {total}")
    lines.append("")
    lines.append(SEP)
    lines.append("  END OF REPORT — SiteMap Guard v3")
    lines.append(SEP)

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# CLI commands
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option()
def cli():
    """🛡️ SiteMap Guard v3 - Bug Bounty Scanner"""
    pass


@cli.command()
@click.argument("url")
@click.option("--output", default="./reports", help="Output directory")
def scan(url: str, output: str):
    """Run the complete pipeline locally."""
    console.print(Panel.fit(
        f"[bold blue]SiteMap Guard v3 Pipeline[/]\nTarget: [cyan]{url}[/]",
        border_style="blue"
    ))

    pipeline = BugBountyPipeline(target_url=url, output_dir=output)

    with console.status("[bold green]Executing Pipeline... (This may take a while)[/]"):
        results = asyncio.run(pipeline.run())

    console.print("\n[bold green]✅ Pipeline Complete![/]")

    # ── DNS Recon ─────────────────────────────────────────────────────────────
    dns_info = results.get("dns_info", {})
    if dns_info:
        dns_table = Table(
            title=f"🌐 DNS Recon — {dns_info.get('domain', url)}",
            border_style="blue", box=box.ROUNDED, show_lines=True,
        )
        dns_table.add_column("Record", style="bold cyan", no_wrap=True)
        dns_table.add_column("Value", style="white")

        if dns_info.get("a_records"):
            dns_table.add_row("A Records", "\n".join(dns_info["a_records"]))
        if dns_info.get("ns_records"):
            dns_table.add_row("NS Records", "\n".join(dns_info["ns_records"]))
        if dns_info.get("mx_records"):
            mx_str = "\n".join(f"{m['preference']} {m['exchange']}" for m in dns_info["mx_records"])
            dns_table.add_row("MX Records", mx_str)
        if dns_info.get("spf"):
            dns_table.add_row("SPF", dns_info["spf"])
        if dns_info.get("cdn"):
            dns_table.add_row("CDN", f"[yellow]{dns_info['cdn']}[/]")
        if dns_info.get("email_provider"):
            dns_table.add_row("Email Provider", dns_info["email_provider"])
        subs = dns_info.get("live_subdomains", [])
        if subs:
            sub_str = "\n".join(
                f"[green]{s['subdomain']}[/]  →  {', '.join(s['ips'])}" for s in subs[:15]
            )
            dns_table.add_row(f"Live Subdomains ({len(subs)})", sub_str)
        console.print(dns_table)

    # ── Live Hosts ────────────────────────────────────────────────────────────
    live_targets = results.get("live_targets", [])
    live_table = Table(
        title=f"Live Hosts Found ({len(live_targets)})",
        border_style="green", box=box.ROUNDED,
    )
    live_table.add_column("URL", style="cyan", max_width=55)
    live_table.add_column("Status", style="magenta", justify="center")
    live_table.add_column("Title", style="yellow", max_width=35)
    live_table.add_column("Tech", style="blue", max_width=30)

    for t in live_targets[:30]:
        status = t.get("status", 0)
        if status == 200:
            s = f"[green]{status}[/]"
        elif status in (301, 302):
            s = f"[yellow]{status}[/]"
        elif status and status >= 400:
            s = f"[red]{status}[/]"
        else:
            s = "[dim]—[/]"
        live_table.add_row(
            t.get("url", ""),
            s,
            (t.get("title") or "")[:35],
            ", ".join(t.get("tech", [])[:3]),
        )
    console.print(live_table)

    # ── Header Findings (only real findings, no connection errors) ────────────
    header_findings = results.get("header_findings", [])
    real_header = [f for f in header_findings if f.get("type") != "connection_error"]

    if real_header:
        seen_hdr: dict = {}
        for f in real_header:
            key = (f.get("type"), f.get("name"))
            seen_hdr.setdefault(key, {"finding": f, "count": 0})
            seen_hdr[key]["count"] += 1

        sev_colors = {"high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        sorted_hdrs = sorted(
            seen_hdr.values(),
            key=lambda x: _severity_rank(x["finding"].get("severity", "info"))
        )

        hdr_table = Table(
            title=f"Header / Security Findings ({len(seen_hdr)} unique)",
            border_style="cyan", box=box.ROUNDED,
        )
        hdr_table.add_column("Sev", no_wrap=True)
        hdr_table.add_column("Count", justify="right", style="magenta")
        hdr_table.add_column("Finding", max_width=55)
        hdr_table.add_column("Sample URL", style="dim cyan", max_width=40)

        for item in sorted_hdrs[:25]:
            f = item["finding"]
            sev = f.get("severity", "info")
            color = sev_colors.get(sev, "white")
            hdr_table.add_row(
                f"[{color}]{sev.upper()}[/]",
                str(item["count"]),
                f.get("name", ""),
                f.get("url", "")[:40],
            )
        console.print(hdr_table)
    else:
        # Show connection summary only — no per-URL error flood
        conn_errors = [f for f in header_findings if f.get("type") == "connection_error"]
        if conn_errors:
            console.print(
                f"[dim yellow]⚠  {len(conn_errors)} URLs unreachable (TLS/connectivity issues). "
                "Scan continued with discovered URLs.[/]"
            )

    # ── Nuclei Findings ───────────────────────────────────────────────────────
    nuclei_findings = results.get("nuclei_findings", [])
    nuc_table = Table(
        title=f"Nuclei Findings ({len(nuclei_findings)})",
        border_style="red", box=box.ROUNDED,
    )
    nuc_table.add_column("Severity", style="red")
    nuc_table.add_column("Name", style="magenta", max_width=45)
    nuc_table.add_column("URL", style="cyan", max_width=50)

    for f in nuclei_findings[:25]:
        info = f.get("info", {})
        nuc_table.add_row(
            info.get("severity", "unknown"),
            info.get("name", "unknown")[:45],
            f.get("url", f.get("matched-at", ""))[:50],
        )
    console.print(nuc_table)

    # ── Threat findings ───────────────────────────────────────────────────────
    threat_findings = results.get("threat_findings", [])
    if threat_findings:
        t3 = Table(title=f"Threat Feed Matches ({len(threat_findings)})",
                   border_style="bold red", box=box.ROUNDED)
        t3.add_column("Severity", style="red")
        t3.add_column("Type", style="magenta")
        t3.add_column("URL", style="cyan")
        for f in threat_findings[:20]:
            t3.add_row(f.get("severity", "high"), f.get("type", ""), f.get("url", ""))
        console.print(t3)

    # ── Summary panel ─────────────────────────────────────────────────────────
    real_live = [t for t in live_targets if t.get("status", 0) not in (0,)]
    js_secrets = results.get("js_secrets", [])
    plugin_findings = results.get("plugin_findings", [])
    total_findings = len(real_header) + len(nuclei_findings) + len(threat_findings) + len(js_secrets) + len(plugin_findings)
    console.print(Panel(
        f"[bold]Scan Summary[/]\n"
        f"  Subdomains Discovered   : [blue]{len(dns_info.get('live_subdomains', []))}[/]\n"
        f"  Live Hosts (confirmed)  : [green]{len(real_live)}[/] / {len(live_targets)}\n"
        f"  Header / Security Issues: [cyan]{len(real_header)}[/]\n"
        f"  Nuclei Findings         : [red]{len(nuclei_findings)}[/]\n"
        f"  Threat Feed Matches     : [red]{len(threat_findings)}[/]\n"
        f"  JS Secrets              : [magenta]{len(js_secrets)}[/]\n"
        f"  Plugin Findings         : [yellow]{len(plugin_findings)}[/]\n"
        f"  Total Findings          : [bold red]{total_findings}[/]",
        border_style="green", title="📊 Results",
    ))

    # ── Save TXT report ───────────────────────────────────────────────────────
    report_path = Path(output) / "scan_report.txt"
    generate_txt_report(results, str(report_path))
    console.print(f"\n[bold yellow]📄 TXT Report saved to:[/] [cyan]{report_path}[/]")

    # ── Save full JSON ────────────────────────────────────────────────────────
    json_path = Path(output) / "full_results.json"
    try:
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=2, default=str)
        console.print(f"[bold yellow]💾 JSON saved to:[/] [cyan]{json_path}[/]")
    except Exception:
        pass


@cli.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
def serve(host: str, port: int):
    """Start the FastAPI backend server."""
    console.print(Panel.fit(
        f"[bold green]Starting FastAPI Server on {host}:{port}[/]",
        border_style="green"
    ))
    uvicorn.run("sitemap_guard.api:app", host=host, port=port, reload=True)


@cli.command()
@click.argument("url")
@click.option("--output", default="./reports", help="Output directory")
@click.option("--full-scan", is_flag=True, default=False,
              help="Run the full vulnerability pipeline before classifying URLs.")
def sitemap(url: str, output: str, full_scan: bool):
    """
    Generate the enhanced sitemap report:
        URL | Status | Classification | Redirect

    Saved as <domain>_report_<YYYYMMDD_HHMMSS>.txt in the output directory.
    """
    console.print(Panel.fit(
        f"[bold blue]Enhanced Sitemap Reporter[/]\n"
        f"Target: [cyan]{url}[/]\n"
        f"Mode  : [yellow]{'Full scan + classify' if full_scan else 'Discovery + classify (fast)'}[/]",
        border_style="blue",
    ))

    async def _run() -> str:
        scan_results: dict = {}
        if full_scan:
            with console.status("[bold green]Running full pipeline...[/]"):
                pipeline = BugBountyPipeline(target_url=url, output_dir=output)
                scan_results = await pipeline.run()

        reporter = EnhancedSitemapReporter(target_url=url, output_dir=output)
        with console.status("[bold green]Discovering URLs and classifying...[/]"):
            return await reporter.generate_enhanced_report(scan_results)

    try:
        report_path = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted by user.[/]")
        return
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise

    console.print(f"\n[bold green]Sitemap report generated:[/] [cyan]{report_path}[/]")


if __name__ == "__main__":
    cli()
