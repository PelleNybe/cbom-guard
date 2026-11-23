"""Rich interactive terminal summary and findings table reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cbom_guard.models import RiskLevel, ScanResult

_RISK_STYLE: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.WARNING: "bold yellow",
    RiskLevel.INFO: "bold cyan",
}


def render_terminal_report(scan_result: ScanResult, console: Console | None = None) -> None:
    """Render a structured Post-Quantum Readiness report to the terminal."""
    out = console or Console()

    summary = Text()
    summary.append("Target: ", style="bold")
    summary.append(f"{scan_result.target_path}\n")
    summary.append("Files Scanned: ", style="bold")
    summary.append(f"{scan_result.files_scanned}\n")
    summary.append("Findings: ", style="bold")
    summary.append(f"{scan_result.critical_count} Critical (Shor) ", style="bold red")
    summary.append("| ")
    summary.append(f"{scan_result.warning_count} Warning (Grover) ", style="bold yellow")
    summary.append("| ")
    summary.append(f"{scan_result.info_count} Info (PQC-Safe)", style="bold cyan")

    out.print(
        Panel(
            summary,
            title="[bold white]cbom-guard — Post-Quantum Cryptography Readiness[/bold white]",
            border_style="blue",
        )
    )

    if not scan_result.findings:
        out.print("[bold green]No cryptographic assets or PQC vulnerabilities detected.[/bold green]")
        return

    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Risk", width=10)
    table.add_column("Rule ID", width=15)
    table.add_column("Algorithm", width=16)
    table.add_column("Threat", width=8)
    table.add_column("Location", ratio=2)
    table.add_column("Hybrid-PQC Target", ratio=2)

    for finding in scan_result.findings:
        risk_text = Text(finding.risk_level.value.upper(), style=_RISK_STYLE[finding.risk_level])
        loc = f"{finding.file_path}:{finding.start_line}:{finding.start_col}"
        table.add_row(
            risk_text,
            finding.rule_id,
            finding.algorithm,
            finding.quantum_vulnerability.value.upper(),
            loc,
            finding.remediation.hybrid_pqc_target,
        )

    out.print(table)
