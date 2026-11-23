"""Phase 1 verification tests for Tree-sitter Python AST scanner and rules."""

from __future__ import annotations

from pathlib import Path

from cbom_guard.models import RiskLevel
from cbom_guard.scanner.ast_parser import ASTParser
from cbom_guard.scanner.rule_engine import RuleEngine

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "python"


def test_python_rule_count() -> None:
    engine = RuleEngine()
    py_rules = [r for r in engine.rules if r.language.value == "python"]
    assert len(py_rules) >= 15


def test_vulnerable_python_fixture_exact_detection() -> None:
    parser = ASTParser()
    engine = RuleEngine()
    parsed = parser.parse_file(FIXTURES_DIR / "vulnerable_crypto.py")
    findings = engine.evaluate(parsed)

    rule_ids = {f.rule_id for f in findings}
    expected_rules = {
        "PY-CRYPTO-001",  # RSA-2048 & RSA-1024
        "PY-CRYPTO-002",  # Weak RSA < 2048
        "PY-CRYPTO-003",  # ECDSA
        "PY-CRYPTO-004",  # DSA
        "PY-CRYPTO-005",  # DH
        "PY-CRYPTO-006",  # Ed25519
        "PY-CRYPTO-008",  # hashes.SHA1
        "PY-HASH-001",    # hashlib.md5
        "PY-HASH-002",    # hashlib.sha1
        "PY-HASH-003",    # hashlib.new("md5")
        "PY-PYCRYPTO-001",
        "PY-PYCRYPTO-003",
        "PY-RSA-001",
        "PY-ECDSA-001",
        "PY-SSL-001",
    }
    assert expected_rules.issubset(rule_ids)

    # Verify exact line numbers for key findings
    rsa_weak = [f for f in findings if f.rule_id == "PY-CRYPTO-002"]
    assert len(rsa_weak) == 1
    assert rsa_weak[0].start_line == 21
    assert rsa_weak[0].start_col >= 1

    md5_findings = [f for f in findings if f.rule_id == "PY-HASH-001"]
    assert len(md5_findings) == 1
    assert md5_findings[0].start_line == 37


def test_safe_python_fixture_zero_false_positives() -> None:
    parser = ASTParser()
    engine = RuleEngine()
    parsed = parser.parse_file(FIXTURES_DIR / "safe_crypto.py")
    findings = engine.evaluate(parsed)

    non_info = [f for f in findings if f.risk_level != RiskLevel.INFO]
    assert non_info == [], f"Unexpected false positives: {[f.rule_id for f in non_info]}"
    assert any(f.rule_id == "PY-SAFE-001" for f in findings)
