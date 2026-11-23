"""Workspace recursive scanner combining Tree-sitter AST rules and X.509 inspection."""

from __future__ import annotations

from pathlib import Path

from cbom_guard.models import Finding, ScanResult
from cbom_guard.scanner.ast_parser import ASTParser, detect_language
from cbom_guard.scanner.cert_scanner import CERT_EXTENSIONS, scan_certificate_file
from cbom_guard.scanner.rule_engine import RuleEngine

IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
    }
)


def _iter_scannable_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]

    files: list[Path] = []
    for item in sorted(target.rglob("*")):
        if any(part in IGNORED_DIRS for part in item.parts):
            continue
        if not item.is_file():
            continue
        if detect_language(item) is not None or item.suffix.lower() in CERT_EXTENSIONS:
            files.append(item)
    return files


def scan_path(
    target: Path,
    rules_dir: Path | None = None,
) -> ScanResult:
    """Scan a file or directory for cryptographic assets and PQC vulnerabilities."""
    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target}")

    parser = ASTParser()
    rules = RuleEngine.load_rules_from_dir(rules_dir) if rules_dir else None
    engine = RuleEngine(rules=rules)

    files = _iter_scannable_files(target)
    all_findings: list[Finding] = []
    files_scanned = 0

    for file_path in files:
        if file_path.suffix.lower() in CERT_EXTENSIONS:
            cert_findings = scan_certificate_file(file_path)
            files_scanned += 1
            all_findings.extend(cert_findings)
        elif detect_language(file_path) is not None:
            parsed = parser.parse_file(file_path)
            files_scanned += 1
            all_findings.extend(engine.evaluate(parsed))

    all_findings.sort(key=lambda f: (f.file_path, f.start_line, f.start_col, f.rule_id))
    return ScanResult(
        target_path=str(target),
        files_scanned=files_scanned,
        findings=all_findings,
    )
