import asyncio
import click
from collections import Counter
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import uvicorn

import sys

from sitemap_guard.pipeline import BugBountyPipeline

console = Console()

# Fix Windows encoding issues for Rich output
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

@click.group()
@click.version_option()
def cli():
    """🛡️ SiteMap Guard v3 - FastAPI Bug Bounty Orchestrator"""
    pass

@cli.command()
@click.argument("url")
@click.option("--output", default="./reports", help="Output directory")
def scan(url: str, output: str):
    """Run the complete pipeline locally."""
    console.print(Panel.fit(f"[bold blue]SiteMap Guard v3 Pipeline[/]\nTarget: [cyan]{url}[/]", border_style="blue"))
    
    pipeline = BugBountyPipeline(target_url=url, output_dir=output)
    
    with console.status("[bold green]Executing Pipeline... (This may take a while)[/]"):
        results = asyncio.run(pipeline.run())
        
    console.print("\n[bold green]✅ Pipeline Complete![/]")
    
    # Print Live Hosts
    live_targets = results.get("live_targets", [])
    table = Table(title=f"Live Hosts Found ({len(live_targets)})", border_style="green")
    table.add_column("URL", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Title", style="yellow")
    table.add_column("Tech", style="blue")
    
    for t in live_targets[:20]: # Top 20
        tech_str = ", ".join(t.get("tech", []))
        table.add_row(t.get("url"), str(t.get("status")), t.get("title", "")[:30], tech_str[:30])
        
    console.print(table)
    
    # Connectivity Diagnostics + Header Findings
    header_findings = results.get("header_findings", [])
    conn_errors = [f for f in header_findings if f.get("type") == "connection_error"]
    if conn_errors:
        err_counts = Counter(f.get("details", "Unknown error") for f in conn_errors)
        diag_table = Table(title=f"Connectivity Issues ({len(conn_errors)})", border_style="yellow")
        diag_table.add_column("Count", style="magenta", justify="right")
        diag_table.add_column("Error", style="yellow")
        for err, count in err_counts.most_common(5):
            diag_table.add_row(str(count), err[:120])
        console.print(diag_table)

    header_issues = [f for f in header_findings if f.get("type") != "connection_error"]
    if header_issues:
        hdr_table = Table(title=f"Header Findings ({len(header_issues)})", border_style="cyan")
        hdr_table.add_column("Severity", style="red")
        hdr_table.add_column("Name", style="magenta")
        hdr_table.add_column("URL", style="cyan")
        hdr_table.add_column("Details", style="yellow")
        for f in header_issues[:20]:
            hdr_table.add_row(
                f.get("severity", "info"),
                f.get("name", "unknown"),
                f.get("url", ""),
                (f.get("details") or "")[:40]
            )
        console.print(hdr_table)

    # Print Findings
    findings = results.get("nuclei_findings", [])
    table2 = Table(title=f"Nuclei Findings ({len(findings)})", border_style="red")
    table2.add_column("Severity", style="red")
    table2.add_column("Name", style="magenta")
    table2.add_column("URL", style="cyan")
    
    for f in findings[:20]:
        info = f.get("info", {})
        table2.add_row(
            info.get("severity", "unknown"),
            info.get("name", "unknown"),
            f.get("url", "")
        )
        
    console.print(table2)
    
    # Print Threat Findings
    threat_findings = results.get("threat_findings", [])
    if threat_findings:
        table3 = Table(title=f"Local Threat Findings ({len(threat_findings)})", border_style="bold red")
        table3.add_column("Severity", style="red")
        table3.add_column("Type", style="magenta")
        table3.add_column("URL", style="cyan")
        
        for f in threat_findings[:20]:
            table3.add_row(
                f.get("severity", "high"),
                f.get("type", "unknown"),
                f.get("url", "")
            )
        console.print(table3)
        
    # Generate Flowchart
    from sitemap_guard.flowchart import generate_flowchart
    if live_targets:
        flowchart_path = Path(output) / "sitemap_flowchart.html"
        generate_flowchart(
            live_targets=live_targets,
            nuclei_findings=results.get("nuclei_findings", []),
            header_findings=results.get("header_findings", []),
            threat_findings=results.get("threat_findings", []),
            output_path=str(flowchart_path)
        )
        console.print(f"\n[bold yellow]🗺️ Sitemap Flowchart saved to:[/] [cyan]{flowchart_path}[/]")
    
    console.print(f"\n[dim]Full results saved to {output}[/]")

@cli.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
def serve(host: str, port: int):
    """Start the FastAPI backend server."""
    console.print(Panel.fit(f"[bold green]Starting FastAPI Server on {host}:{port}[/]", border_style="green"))
    uvicorn.run("sitemap_guard.api:app", host=host, port=port, reload=True)

if __name__ == "__main__":
    cli()
