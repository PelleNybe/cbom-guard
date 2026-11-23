"""Phase 4 tests for C, C++, Go, JavaScript AST scanning and X.509 certificate scanning."""

from __future__ import annotations

from pathlib import Path

from cbom_guard.models import AssetType, Language, QuantumVulnerability, RiskLevel
from cbom_guard.scanner.ast_parser import ASTParser
from cbom_guard.scanner.cert_scanner import scan_certificate_file
from cbom_guard.scanner.rule_engine import RuleEngine
from cbom_guard.scanner.workspace import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def test_c_openssl_scanner() -> None:
    parser = ASTParser()
    engine = RuleEngine()
    parsed = parser.parse_file(FIXTURES / "c_cpp" / "vulnerable_openssl.c")
    findings = engine.evaluate(parsed)
    rule_ids = {f.rule_id for f in findings}
    assert {
        "C-OPENSSL-001",
        "C-OPENSSL-002",
        "C-OPENSSL-003",
        "C-OPENSSL-004",
        "C-OPENSSL-SAFE-001",
    }.issubset(rule_ids)
    # Commented EVP_md5() on line 6 must not be detected
    assert all(f.start_line != 6 for f in findings)


def test_cpp_openssl_scanner() -> None:
    parser = ASTParser()
    engine = RuleEngine()
    parsed = parser.parse_file(FIXTURES / "c_cpp" / "vulnerable_openssl.cpp")
    findings = engine.evaluate(parsed)
    rule_ids = {f.rule_id for f in findings}
    assert {"CPP-OPENSSL-001", "CPP-OPENSSL-002"}.issubset(rule_ids)


def test_go_crypto_scanner() -> None:
    parser = ASTParser()
    engine = RuleEngine()
    parsed = parser.parse_file(FIXTURES / "go" / "vulnerable_crypto.go")
    findings = engine.evaluate(parsed)
    rule_ids = {f.rule_id for f in findings}
    assert {"GO-CRYPTO-001", "GO-CRYPTO-002", "GO-CRYPTO-004", "GO-CRYPTO-005"}.issubset(rule_ids)
    # Comment on line 13 must not trigger
    assert all(f.start_line != 13 for f in findings)


def test_javascript_crypto_scanner() -> None:
    parser = ASTParser()
    engine = RuleEngine()
    parsed = parser.parse_file(FIXTURES / "javascript" / "vulnerable_crypto.js")
    findings = engine.evaluate(parsed)
    rule_ids = {f.rule_id for f in findings}
    assert {"JS-CRYPTO-001", "JS-CRYPTO-002", "JS-CRYPTO-003", "JS-JWT-001"}.issubset(rule_ids)
    # Safe sha384 on line 12 must not trigger JS-CRYPTO-002
    sha1_findings = [f for f in findings if f.rule_id == "JS-CRYPTO-002"]
    assert len(sha1_findings) == 1
    assert sha1_findings[0].start_line == 9


def test_x509_certificate_scanner() -> None:
    rsa_findings = scan_certificate_file(FIXTURES / "certs" / "rsa2048.pem")
    assert len(rsa_findings) == 1
    rsa_f = rsa_findings[0]
    assert rsa_f.asset_type == AssetType.CERTIFICATE
    assert rsa_f.language == Language.X509
    assert rsa_f.algorithm == "RSA"
    assert rsa_f.quantum_vulnerability == QuantumVulnerability.SHOR
    assert rsa_f.risk_level == RiskLevel.CRITICAL
    assert rsa_f.certificate is not None
    assert rsa_f.certificate.key_size == 2048
    assert rsa_f.certificate.signature_hash_algorithm == "SHA256"

    ec_findings = scan_certificate_file(FIXTURES / "certs" / "ecdsa_p256.crt")
    assert len(ec_findings) == 1
    ec_f = ec_findings[0]
    assert ec_f.algorithm == "ECDSA"
    assert ec_f.certificate is not None
    assert ec_f.certificate.key_size == 256


def test_workspace_recursive_scan() -> None:
    result = scan_path(FIXTURES)
    assert result.files_scanned >= 7
    assert result.critical_count > 0
    assert result.warning_count > 0
    assert result.info_count > 0


def test_all_rule_ids_are_unique() -> None:
    engine = RuleEngine()
    ids = [r.id for r in engine.rules]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs detected!"
    assert len(ids) >= 36


def test_non_cert_pem_file_gracefully_ignored(tmp_path: Path) -> None:
    fake_pem = tmp_path / "private.pem"
    fake_pem.write_text("-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n")
    assert scan_certificate_file(fake_pem) == []


def test_libsodium_and_pbkdf2_rules() -> None:
    parser = ASTParser()
    engine = RuleEngine()

    c_parsed = parser.parse_bytes(
        b'#include <sodium.h>\nvoid f() { unsigned char pk[32], sk[32]; crypto_box_keypair(pk, sk); }\n',
        path="sodium_test.c",
        language=Language.C,
    )
    assert any(f.rule_id == "C-SODIUM-001" for f in engine.evaluate(c_parsed))

    py_parsed = parser.parse_bytes(
        b'import hashlib\ndk = hashlib.pbkdf2_hmac("sha1", b"pw", b"salt", 100000)\n',
        path="kdf_test.py",
        language=Language.PYTHON,
    )
    assert any(f.rule_id == "PY-HASH-004" for f in engine.evaluate(py_parsed))
