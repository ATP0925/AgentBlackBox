"""Rich terminal rendering for code review reports."""

from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from agentblackbox.models.finding import Severity
from agentblackbox.models.report import ReviewReport


SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold dark_orange",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim white",
}

SEVERITY_BADGES = {
    Severity.CRITICAL: "[bold white on red] CRITICAL [/]",
    Severity.HIGH: "[bold white on dark_orange]  HIGH   [/]",
    Severity.MEDIUM: "[bold black on yellow] MEDIUM  [/]",
    Severity.LOW: "[bold black on cyan]   LOW   [/]",
    Severity.INFO: "[bold white on grey30]  INFO   [/]",
}


def render_terminal_report(report: ReviewReport, console: Optional[Console] = None) -> None:
    """Render a comprehensive review report to the terminal using Rich."""
    console = console or Console()

    # 1. Header
    title_text = Text("AgentBlackBox AI Code Review & Analysis", style="bold cyan")
    meta_info = f"Target: [bold]{report.target}[/]  •  Analyzed: [bold]{len(report.analyzed_files)} files[/]  •  Duration: [bold]{report.execution_time_ms:.1f}ms[/]"
    if report.model_name:
        meta_info += f"  •  Provider: [bold]{report.model_name}[/]"

    console.print(Panel(Text.from_markup(meta_info), title=title_text, border_style="cyan"))

    # 2. Summary Table
    counts = report.severity_counts
    summary_table = Table(title="Severity Summary", show_header=True, header_style="bold magenta", expand=True)
    summary_table.add_column("Severity Level", justify="left")
    summary_table.add_column("Count", justify="right")
    summary_table.add_column("Status", justify="left")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        c = counts.get(sev.value, 0)
        style = SEVERITY_STYLES.get(sev, "white")
        status_desc = "Action Required" if c > 0 and sev in (Severity.CRITICAL, Severity.HIGH) else ("Review Advised" if c > 0 else "Clean")
        summary_table.add_row(
            f"[{style}]{sev.value}[/]",
            f"[{style}]{c}[/]",
            f"[{style}]{status_desc}[/]",
        )

    console.print(summary_table)
    console.print("")

    # 3. Individual Findings
    if not report.findings:
        console.print(Panel("[bold green]✓ Clean bill of health! No issues found across analyzed files.[/]", border_style="green"))
        return

    console.print(f"[bold underline]Detailed Findings ({len(report.findings)} items):[/]")
    console.print("")

    for idx, f in enumerate(report.findings, start=1):
        badge = SEVERITY_BADGES.get(f.severity, f"[{f.severity.value}]")
        loc = f"{f.file_path}:{f.line_start}"
        if f.line_end and f.line_end != f.line_start:
            loc += f"-{f.line_end}"

        rule_tag = f"Rule: {f.rule_id}"
        if f.cwe_id:
            rule_tag += f" | {f.cwe_id}"

        heading = f"{badge} #{idx} [bold]{f.title}[/]  [dim]({loc})[/]  [italic dim]({rule_tag})[/]"
        console.print(heading)

        # Message & Impact
        console.print(f"  [bold]Problem:[/] {f.message}")
        if f.why_it_matters:
            console.print(f"  [bold orange3]Impact:[/]  {f.why_it_matters}")

        # Suggested Fix Code Snippet
        if f.suggested_fix:
            fix_syntax = Syntax(f.suggested_fix.strip(), "python", theme="monokai", line_numbers=False)
            console.print("  [bold green]Suggested Remediation:[/]")
            console.print(Panel(fix_syntax, border_style="dim green", padding=(0, 1)))

        console.print("")

    # 4. Final Verdict
    if report.has_critical_or_high:
        console.print(Panel("[bold red]✗ REVIEW FAILED: Critical or High severity findings detected. Please resolve these before merging.[/]", border_style="red"))
    else:
        console.print(Panel("[bold green]✓ REVIEW PASSED: No Critical or High issues found. Minor suggestions can be reviewed at discretion.[/]", border_style="green"))

