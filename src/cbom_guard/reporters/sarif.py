"""Standards-compliant SARIF 2.1.0 exporter for GitHub Code Scanning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cbom_guard import __version__
from cbom_guard.models import Finding, RiskLevel, ScanResult

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

_RISK_TO_SARIF_LEVEL: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "error",
    RiskLevel.WARNING: "warning",
    RiskLevel.INFO: "note",
}

_RISK_TO_SECURITY_SEVERITY: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "9.0",
    RiskLevel.WARNING: "5.5",
    RiskLevel.INFO: "1.0",
}


def _normalize_uri(file_path: str, base_path: str | None = None) -> str:
    p = Path(file_path)
    if base_path is not None:
        try:
            rel = p.resolve().relative_to(Path(base_path).resolve())
            return rel.as_posix()
        except ValueError:
            pass
    return p.as_posix().lstrip("./")


def _build_rule_entry(finding: Finding) -> dict[str, Any]:
    markdown_help = (
        f"### {finding.rule_name}\n\n"
        f"**Quantum Threat:** `{finding.quantum_vulnerability.value.upper()}` | "
        f"**NIST PQC Status:** `{finding.nist_pqc_status}` | "
        f"**CWE:** `{finding.cwe}`\n\n"
        f"{finding.description}\n\n"
        f"#### Hybrid-PQC Remediation Target: `{finding.remediation.hybrid_pqc_target}`\n"
        f"{finding.remediation.summary}\n"
    )
    if finding.remediation.code_example.strip():
        markdown_help += f"\n```text\n{finding.remediation.code_example.strip()}\n```\n"

    return {
        "id": finding.rule_id,
        "name": finding.rule_name,
        "shortDescription": {"text": finding.rule_name},
        "fullDescription": {"text": finding.description},
        "helpUri": "https://github.com/CoraxCoLAB/cbom-guard",
        "help": {
            "text": f"{finding.remediation.summary} (Target: {finding.remediation.hybrid_pqc_target})",
            "markdown": markdown_help,
        },
        "defaultConfiguration": {
            "level": _RISK_TO_SARIF_LEVEL[finding.risk_level],
        },
        "properties": {
            "tags": [
                "security",
                "cryptography",
                "post-quantum",
                finding.cwe,
                f"quantum-{finding.quantum_vulnerability.value}",
            ],
            "security-severity": _RISK_TO_SECURITY_SEVERITY[finding.risk_level],
            "precision": "high",
        },
    }


def generate_sarif(scan_result: ScanResult, base_path: str | None = None) -> str:
    """Serialize a ScanResult into a SARIF 2.1.0 JSON string."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    rule_indices: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in scan_result.findings:
        if finding.rule_id not in rules_by_id:
            rule_indices[finding.rule_id] = len(rules_by_id)
            rules_by_id[finding.rule_id] = _build_rule_entry(finding)

        uri = _normalize_uri(finding.file_path, base_path=base_path)
        message_text = (
            f"[{finding.quantum_vulnerability.value.upper()}] {finding.rule_name}: "
            f"{finding.remediation.summary} (Target: {finding.remediation.hybrid_pqc_target})"
        )

        region: dict[str, Any] = {
            "startLine": max(1, finding.start_line),
            "startColumn": max(1, finding.start_col),
            "endLine": max(1, finding.end_line),
            "endColumn": max(1, finding.end_col),
        }
        if finding.snippet:
            region["snippet"] = {"text": finding.snippet}

        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_indices[finding.rule_id],
                "level": _RISK_TO_SARIF_LEVEL[finding.risk_level],
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": region,
                        }
                    }
                ],
            }
        )

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cbom-guard",
                        "organization": "Corax CoLAB",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/CoraxCoLAB/cbom-guard",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)
