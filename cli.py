#!/usr/bin/env python3
import click
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.scanner import ComplianceScanner
from core.reporter import ReportGenerator
from core.models import Framework

console = Console()

@click.group()
def cli():
    """AI-Powered Compliance & Security Checker CLI"""
    pass

@cli.command()
@click.argument('paths', nargs=-1, required=True)
@click.option('--out', '-o', default='./reports', help='Output directory for reports')
@click.option('--format', '-f', 'formats', multiple=True, default=['json'], 
              type=click.Choice(['json', 'html']), help='Output format(s)')
@click.option('--framework', multiple=True, type=click.Choice(['iso27001', 'soc2', 'gdpr']), 
              help='Limit scan to specific frameworks')
def scan(paths, out, formats, framework):
    """Scan paths for compliance violations."""
    console.print("🔍 Starting compliance scan...", style="bold blue")
    
    scanner = ComplianceScanner()
    reporter = ReportGenerator(out)
    
    # Convert framework strings to enum objects
    framework_enums = [Framework(f) for f in framework] if framework else None
    
    # Perform scan
    result = scanner.scan_paths(list(paths), framework_enums)
    
    # Display summary
    _display_scan_summary(result)
    
    # Generate reports
    output_files = []
    for fmt in formats:
        if fmt == 'json':
            json_path = reporter.generate_json_report(result)
            output_files.append(json_path)
        elif fmt == 'html':
            html_path = reporter.generate_html_report(result)
            output_files.append(html_path)
    
    console.print(f"\n📄 Reports generated:", style="bold green")
    for file_path in output_files:
        console.print(f"  • {file_path}")
    
    # Return exit code based on severity of findings
    critical_count = sum(1 for f in result.findings if f.severity == "critical")
    high_count = sum(1 for f in result.findings if f.severity == "high")
    
    if critical_count > 0:
        sys.exit(2)  # Critical issues found
    elif high_count > 0:
        sys.exit(1)  # High severity issues found
    else:
        sys.exit(0)  # No critical/high issues

def _display_scan_summary(result):
    """Display scan results summary in console."""
    # Summary table
    summary_table = Table(title="Scan Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="bold")
    
    summary_table.add_row("Files Scanned", str(result.summary.total_files_scanned))
    summary_table.add_row("Total Findings", str(result.summary.total_findings))
    summary_table.add_row("Critical Issues", f"[red]{result.summary.findings_by_severity['critical']}[/red]")
    summary_table.add_row("High Issues", f"[yellow]{result.summary.findings_by_severity['high']}[/yellow]")
    summary_table.add_row("Medium Issues", str(result.summary.findings_by_severity['medium']))
    summary_table.add_row("Low Issues", f"[green]{result.summary.findings_by_severity['low']}[/green]")
    summary_table.add_row("Scan Duration", f"{result.summary.scan_duration_seconds:.2f}s")
    
    console.print(summary_table)
    
    # Top risks
    if result.top_risks:
        console.print("\n🚨 Top Security Risks:", style="bold red")
        for i, risk in enumerate(result.top_risks[:5], 1):
            console.print(f"  {i}. {risk.file_path} - {risk.why_it_matters}")
    
    # Recommendations
    if result.recommendations:
        recommendations_panel = Panel(
            "\n".join(f"• {rec}" for rec in result.recommendations),
            title="Priority Recommendations",
            border_style="green"
        )
        console.print(recommendations_panel)

@cli.command()
@click.option('--id', 'scan_id', help='Scan ID to generate report for')
@click.option('--format', '-f', default='html', type=click.Choice(['json', 'html']), 
              help='Report format')
def report(scan_id, format):
    """Generate report from previous scan (placeholder for full implementation)."""
    console.print("Report generation from scan ID not implemented in this demo version.", style="yellow")
    console.print("Use the scan command with --format option instead.", style="yellow")

if __name__ == '__main__':
    cli()
