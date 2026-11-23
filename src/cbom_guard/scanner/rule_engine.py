"""YAML rule loader and AST pattern matching engine."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from cbom_guard.models import (
    ArgConstraint,
    AssetType,
    ConstraintOperator,
    Finding,
    Language,
    ParsedCall,
    ParsedFile,
    Rule,
    RuleFile,
)

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _matches_import_requirement(required_imports: list[str], parsed_file: ParsedFile) -> bool:
    """Return True if at least one required import/include is present in the file."""
    if not required_imports:
        return True
    all_imported = set(parsed_file.imported_modules) | set(parsed_file.imports.values())
    for req in required_imports:
        for imp in all_imported:
            if imp == req or imp.startswith(f"{req}.") or imp.startswith(f"{req}/") or req in imp:
                return True
    return False


def _matches_target(candidate: str, patterns: list[str]) -> bool:
    return any(candidate == pat or candidate.endswith(f".{pat}") for pat in patterns)


def _evaluate_constraint(constraint: ArgConstraint, call: ParsedCall) -> bool:
    """Evaluate a single argument constraint against a ParsedCall."""
    if isinstance(constraint.param, int):
        if constraint.param < 0 or constraint.param >= len(call.args):
            return False
        actual: Any = call.args[constraint.param]
    else:
        if constraint.param not in call.kwargs:
            return False
        actual = call.kwargs[constraint.param]

    if actual is None:
        return False

    expected = constraint.value
    op = constraint.op

    if op == ConstraintOperator.EQ:
        return bool(actual == expected)
    if op == ConstraintOperator.NEQ:
        return bool(actual != expected)
    if op == ConstraintOperator.IN:
        if isinstance(expected, list):
            if isinstance(actual, str):
                return actual in expected or any(actual.endswith(f".{e}") for e in expected if isinstance(e, str))
            return actual in expected
        return False
    if op == ConstraintOperator.NOT_IN:
        if isinstance(expected, list):
            return actual not in expected
        return True
    if op == ConstraintOperator.REGEX:
        return bool(re.search(str(expected), str(actual)))

    # Numeric comparisons
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        if op == ConstraintOperator.LT:
            return actual < expected
        if op == ConstraintOperator.LTE:
            return actual <= expected
        if op == ConstraintOperator.GT:
            return actual > expected
        if op == ConstraintOperator.GTE:
            return actual >= expected

    return False


class RuleEngine:
    """Loads YAML rules and evaluates them against Tree-sitter ParsedFile objects."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules: list[Rule] = rules if rules is not None else self.load_default_rules()
        self._rules_by_language: dict[Language, list[Rule]] = {}
        for rule in self.rules:
            self._rules_by_language.setdefault(rule.language, []).append(rule)

    @classmethod
    def load_default_rules(cls) -> list[Rule]:
        """Load all built-in YAML rule files from src/cbom_guard/rules/."""
        return cls.load_rules_from_dir(DEFAULT_RULES_DIR)

    @classmethod
    def load_rules_from_dir(cls, rules_dir: Path) -> list[Rule]:
        """Load and validate all *.yaml / *.yml rule files in a directory."""
        loaded: list[Rule] = []
        if not rules_dir.exists():
            return loaded
        for yaml_path in sorted(rules_dir.glob("*.y*ml")):
            raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            if not raw:
                continue
            rule_file = RuleFile.model_validate(raw)
            loaded.extend(rule_file.rules)
        return loaded

    def evaluate(self, parsed_file: ParsedFile) -> list[Finding]:
        """Evaluate all applicable rules for the file's language and return Findings."""
        lang_rules = self._rules_by_language.get(parsed_file.language, [])
        findings: list[Finding] = []
        seen: set[tuple[str, str, int, int]] = set()

        for rule in lang_rules:
            if not _matches_import_requirement(rule.match.imports, parsed_file):
                continue

            if rule.match.callees:
                for call in parsed_file.calls:
                    if not (
                        _matches_target(call.resolved_callee, rule.match.callees)
                        or _matches_target(call.callee, rule.match.callees)
                    ):
                        continue
                    if rule.match.arg_constraints and not all(
                        _evaluate_constraint(c, call) for c in rule.match.arg_constraints
                    ):
                        continue

                    key = (rule.id, parsed_file.path, call.start_line, call.start_col)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self._build_finding(
                            rule=rule,
                            parsed_file=parsed_file,
                            start_line=call.start_line,
                            start_col=call.start_col,
                            end_line=call.end_line,
                            end_col=call.end_col,
                            snippet=call.snippet,
                            matched_symbol=call.resolved_callee,
                        )
                    )

            if rule.match.symbols:
                for sym in parsed_file.symbols:
                    if not (
                        _matches_target(sym.resolved_symbol, rule.match.symbols)
                        or _matches_target(sym.symbol, rule.match.symbols)
                    ):
                        continue
                    key = (rule.id, parsed_file.path, sym.start_line, sym.start_col)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self._build_finding(
                            rule=rule,
                            parsed_file=parsed_file,
                            start_line=sym.start_line,
                            start_col=sym.start_col,
                            end_line=sym.end_line,
                            end_col=sym.end_col,
                            snippet=sym.snippet,
                            matched_symbol=sym.resolved_symbol,
                        )
                    )

        findings.sort(key=lambda f: (f.file_path, f.start_line, f.start_col, f.rule_id))
        return findings

    def _build_finding(
        self,
        rule: Rule,
        parsed_file: ParsedFile,
        start_line: int,
        start_col: int,
        end_line: int,
        end_col: int,
        snippet: str,
        matched_symbol: str,
    ) -> Finding:
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            file_path=parsed_file.path,
            language=parsed_file.language,
            asset_type=AssetType.ALGORITHM,
            algorithm=rule.algorithm,
            primitive=rule.primitive,
            parameter_set=rule.parameter_set,
            classical_security_level=rule.classical_security_level,
            nist_quantum_security_level=rule.nist_quantum_security_level,
            crypto_functions=rule.crypto_functions,
            quantum_vulnerability=rule.quantum_vulnerability,
            risk_level=rule.risk_level,
            cwe=rule.cwe,
            nist_pqc_status=rule.nist_pqc_status,
            start_line=start_line,
            start_col=start_col,
            end_line=end_line,
            end_col=end_col,
            snippet=snippet,
            matched_symbol=matched_symbol,
            description=rule.description.strip(),
            remediation=rule.remediation,
        )
