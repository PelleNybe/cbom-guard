"""Real X.509 certificate (.pem, .crt, .cer, .der) analyzer using cryptography.x509."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from cbom_guard.models import (
    AssetType,
    CertificateMetadata,
    Finding,
    Language,
    QuantumVulnerability,
    Remediation,
    RiskLevel,
)

CERT_EXTENSIONS: frozenset[str] = frozenset({".pem", ".crt", ".cer", ".der"})
_PEM_CERT_PATTERN = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
    re.DOTALL,
)


def _inspect_public_key(cert: x509.Certificate) -> tuple[str, int | None, str | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size, str(pub.key_size)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA", pub.key_size, pub.curve.name
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size, str(pub.key_size)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448, "448"
    return type(pub).__name__, None, None


def _load_certificates(raw: bytes, suffix: str) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    if b"-----BEGIN CERTIFICATE-----" in raw:
        for block in _PEM_CERT_PATTERN.findall(raw):
            try:
                certs.append(x509.load_pem_x509_certificate(block))
            except ValueError:
                continue
        return certs

    if suffix in (".der", ".cer", ".crt"):
        try:
            certs.append(x509.load_der_x509_certificate(raw))
        except ValueError:
            return []
    return certs


def scan_certificate_file(path: Path) -> list[Finding]:
    """Parse an X.509 certificate file and return PQC readiness findings."""
    if path.suffix.lower() not in CERT_EXTENSIONS:
        return []

    raw = path.read_bytes()
    certs = _load_certificates(raw, path.suffix.lower())
    if not certs:
        return []

    now = datetime.now(tz=UTC)
    findings: list[Finding] = []

    for idx, cert in enumerate(certs, start=1):
        algo, key_size, param_set = _inspect_public_key(cert)
        sig_hash = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else None
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        is_expired = not_after < now
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        meta = CertificateMetadata(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=hex(cert.serial_number),
            not_valid_before=not_before.isoformat(),
            not_valid_after=not_after.isoformat(),
            is_expired=is_expired,
            public_key_algorithm=algo,
            key_size=key_size,
            signature_hash_algorithm=sig_hash,
            fingerprint_sha256=fingerprint,
        )

        is_shor_vulnerable = algo in ("RSA", "ECDSA", "DSA", "Ed25519", "Ed448")
        weak_sig = sig_hash in ("MD5", "SHA1")
        weak_rsa = algo == "RSA" and key_size is not None and key_size < 2048

        if is_shor_vulnerable:
            risk = RiskLevel.CRITICAL
            q_vuln = QuantumVulnerability.SHOR
            nist_status = "disallowed" if (weak_rsa or weak_sig) else "deprecated-by-2030"
            cwe = "CWE-326" if weak_rsa else ("CWE-328" if weak_sig else "CWE-327")
        else:
            risk = RiskLevel.INFO
            q_vuln = QuantumVulnerability.NONE
            nist_status = "cnsa-2.0-compliant"
            cwe = "CWE-327"

        expiry_note = " (EXPIRED)" if is_expired else ""
        sig_note = f", signature hash {sig_hash}" if sig_hash else ""
        desc = (
            f"X.509 certificate #{idx} for '{meta.subject}' uses {algo}"
            f"{f'-{key_size}' if key_size else ''}{sig_note}{expiry_note}. "
            f"Valid until {meta.not_valid_after}."
        )
        if is_shor_vulnerable:
            desc += " Public key algorithm is vulnerable to Shor's algorithm on a quantum computer."

        findings.append(
            Finding(
                rule_id="X509-CERT-001",
                rule_name=f"X.509 Certificate ({algo}{f'-{key_size}' if key_size else ''})",
                file_path=str(path),
                language=Language.X509,
                asset_type=AssetType.CERTIFICATE,
                algorithm=algo,
                primitive="signature",
                parameter_set=param_set,
                classical_security_level=112 if algo == "RSA" and key_size == 2048 else (128 if algo in ("ECDSA", "Ed25519") else None),
                nist_quantum_security_level=0 if is_shor_vulnerable else 3,
                crypto_functions=["verify"],
                quantum_vulnerability=q_vuln,
                risk_level=risk,
                cwe=cwe,
                nist_pqc_status=nist_status,
                start_line=1,
                start_col=1,
                end_line=1,
                end_col=1,
                snippet=f"Subject: {meta.subject} | Key: {algo}-{key_size} | SigHash: {sig_hash}",
                matched_symbol=f"{algo}-{key_size}" if key_size else algo,
                description=desc,
                remediation=Remediation(
                    summary=(
                        "Plan PKI migration to ML-DSA-65 (FIPS 204) or composite/hybrid "
                        "X.509 certificates (e.g., OpenSSL 3.5+ / oqs-provider)."
                    ),
                    hybrid_pqc_target="ML-DSA-65 / Hybrid X.509",
                    code_example=(
                        "# Generate an ML-DSA-65 certificate with OpenSSL + oqsprovider\n"
                        "openssl req -x509 -new -newkey mldsa65 -keyout pqc.key -out pqc.crt -days 365 -nodes"
                    ),
                ),
                certificate=meta,
            )
        )

    return findings
