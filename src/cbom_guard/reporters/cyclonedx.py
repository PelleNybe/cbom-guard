"""Standards-compliant CycloneDX 1.6 CBOM (Cryptographic Bill of Materials) exporter."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
)
from cyclonedx.model.tool import Tool
from cyclonedx.model.vulnerability import (
    BomTarget,
    Vulnerability,
    VulnerabilityRating,
    VulnerabilitySeverity,
)
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from cbom_guard import __version__
from cbom_guard.models import AssetType, Finding, RiskLevel, ScanResult

_PRIMITIVE_MAP: dict[str, CryptoPrimitive] = {
    "ae": CryptoPrimitive.AE,
    "block-cipher": CryptoPrimitive.BLOCK_CIPHER,
    "combiner": CryptoPrimitive.COMBINER,
    "drbg": CryptoPrimitive.DRBG,
    "hash": CryptoPrimitive.HASH,
    "kdf": CryptoPrimitive.KDF,
    "kem": CryptoPrimitive.KEM,
    "key-agreement": CryptoPrimitive.KEY_AGREE,
    "key-wrap": CryptoPrimitive.KEY_WRAP,
    "mac": CryptoPrimitive.MAC,
    "pke": CryptoPrimitive.PKE,
    "signature": CryptoPrimitive.SIGNATURE,
    "stream-cipher": CryptoPrimitive.STREAM_CIPHER,
    "xof": CryptoPrimitive.XOF,
    "other": CryptoPrimitive.OTHER,
}

_FUNCTION_MAP: dict[str, CryptoFunction] = {
    "decapsulate": CryptoFunction.DECAPSULATE,
    "decrypt": CryptoFunction.DECRYPT,
    "digest": CryptoFunction.DIGEST,
    "encapsulate": CryptoFunction.ENCAPSULATE,
    "encrypt": CryptoFunction.ENCRYPT,
    "generate": CryptoFunction.GENERATE,
    "keyderive": CryptoFunction.KEYDERIVE,
    "keygen": CryptoFunction.KEYGEN,
    "sign": CryptoFunction.SIGN,
    "tag": CryptoFunction.TAG,
    "verify": CryptoFunction.VERIFY,
    "other": CryptoFunction.OTHER,
}

_SEVERITY_MAP: dict[RiskLevel, VulnerabilitySeverity] = {
    RiskLevel.CRITICAL: VulnerabilitySeverity.CRITICAL,
    RiskLevel.WARNING: VulnerabilitySeverity.MEDIUM,
    RiskLevel.INFO: VulnerabilitySeverity.INFO,
}


def _map_primitive(primitive: str) -> CryptoPrimitive:
    return _PRIMITIVE_MAP.get(primitive.lower().strip(), CryptoPrimitive.OTHER)


def _map_functions(functions: list[str]) -> list[CryptoFunction]:
    mapped = [_FUNCTION_MAP[f.lower().strip()] for f in functions if f.lower().strip() in _FUNCTION_MAP]
    return mapped or [CryptoFunction.UNKNOWN]


def _build_component_for_finding(finding: Finding, idx: int) -> tuple[Component, BomRef]:
    bom_ref_str = f"cbom-asset-{idx}-{finding.rule_id}"
    bom_ref = BomRef(bom_ref_str)

    if finding.asset_type == AssetType.CERTIFICATE and finding.certificate is not None:
        cert = finding.certificate
        not_before = datetime.fromisoformat(cert.not_valid_before)
        not_after = datetime.fromisoformat(cert.not_valid_after)
        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.CERTIFICATE,
            certificate_properties=CertificateProperties(
                subject_name=cert.subject,
                issuer_name=cert.issuer,
                not_valid_before=not_before,
                not_valid_after=not_after,
                certificate_format="X.509",
                certificate_extension=finding.file_path.rsplit(".", 1)[-1]
                if "." in finding.file_path
                else "pem",
            ),
        )
        comp_name = f"X.509 Certificate ({cert.public_key_algorithm}-{cert.key_size or 'unknown'})"
    else:
        algo_props = AlgorithmProperties(
            primitive=_map_primitive(finding.primitive),
            parameter_set_identifier=finding.parameter_set,
            crypto_functions=_map_functions(finding.crypto_functions),
            classical_security_level=finding.classical_security_level,
            nist_quantum_security_level=finding.nist_quantum_security_level,
        )
        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=algo_props,
        )
        comp_name = (
            f"{finding.algorithm}-{finding.parameter_set}"
            if finding.parameter_set
            else finding.algorithm
        )

    occurrence = Occurrence(
        location=finding.file_path,
        line=finding.start_line,
        offset=finding.start_col,
        symbol=finding.matched_symbol,
        additional_context=finding.snippet[:200],
    )

    properties = [
        Property(name="cbom-guard:rule-id", value=finding.rule_id),
        Property(
            name="cbom-guard:quantum-vulnerability",
            value=finding.quantum_vulnerability.value,
        ),
        Property(name="cbom-guard:risk-level", value=finding.risk_level.value),
        Property(name="cbom-guard:nist-pqc-status", value=finding.nist_pqc_status),
        Property(name="cbom-guard:hybrid-pqc-target", value=finding.remediation.hybrid_pqc_target),
    ]

    component = Component(
        name=comp_name,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=bom_ref,
        description=finding.description,
        crypto_properties=crypto_props,
        evidence=ComponentEvidence(occurrences=[occurrence]),
        properties=properties,
    )
    return component, bom_ref


def generate_cyclonedx_cbom(scan_result: ScanResult) -> str:
    """Serialize a ScanResult into a CycloneDX 1.6 CBOM JSON string."""
    bom = Bom()
    bom.metadata = BomMetaData(
        tools=[
            Tool(
                vendor="Corax CoLAB",
                name="cbom-guard",
                version=__version__,
            )
        ],
        component=Component(
            name=scan_result.target_path,
            type=ComponentType.APPLICATION,
            bom_ref=BomRef("cbom-target-application"),
        ),
    )

    for idx, finding in enumerate(scan_result.findings, start=1):
        component, bom_ref = _build_component_for_finding(finding, idx)
        bom.components.add(component)

        if finding.risk_level in (RiskLevel.CRITICAL, RiskLevel.WARNING):
            cwe_num: int | None = None
            if finding.cwe.upper().startswith("CWE-"):
                raw_num = finding.cwe.split("-", 1)[1]
                if raw_num.isdigit():
                    cwe_num = int(raw_num)

            vuln = Vulnerability(
                id=f"{finding.rule_id}-{idx}",
                description=f"{finding.description} Remediation: {finding.remediation.summary}",
                recommendation=finding.remediation.summary,
                cwes=[cwe_num] if cwe_num is not None else [],
                ratings=[
                    VulnerabilityRating(
                        severity=_SEVERITY_MAP[finding.risk_level],
                    )
                ],
                affects=[BomTarget(ref=bom_ref.value or f"cbom-asset-{idx}-{finding.rule_id}")],
            )
            bom.vulnerabilities.add(vuln)

    outputter = JsonV1Dot6(bom)
    return outputter.output_as_string(indent=2)


def validate_cyclonedx_cbom(cbom_json: str) -> list[Any]:
    """Validate a CycloneDX 1.6 CBOM JSON string against the official schema.

    Returns an empty list if valid, or a list of validation errors.
    """
    validator = JsonStrictValidator(SchemaVersion.V1_6)
    errors = validator.validate_str(cbom_json)
    if errors is None:
        return []
    if isinstance(errors, list):
        return errors
    return [errors]
