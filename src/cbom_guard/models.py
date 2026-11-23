"""Pydantic v2 data models for cbom-guard rules, AST nodes, findings, and scan results."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    """Severity classification aligned with PQC threat urgency."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class QuantumVulnerability(StrEnum):
    """Quantum cryptanalytic threat model."""

    SHOR = "shor"
    GROVER = "grover"
    NONE = "none"


class AssetType(StrEnum):
    """CycloneDX 1.6 cryptographic asset type."""

    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"


class Language(StrEnum):
    """Supported source code and artifact languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    C = "c"
    CPP = "cpp"
    GO = "go"
    X509 = "x509"


class ConstraintOperator(StrEnum):
    """Supported operators for AST argument constraints."""

    EQ = "eq"
    NEQ = "neq"
    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    IN = "in"
    NOT_IN = "not_in"
    REGEX = "regex"


class ArgConstraint(BaseModel):
    """Constraint evaluated against a call's positional or keyword arguments."""

    param: str | int
    op: ConstraintOperator
    value: Any


class RuleMatch(BaseModel):
    """AST matching specification for a detection rule."""

    imports: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    symbols: list[str] = Field(default_factory=list)
    arg_constraints: list[ArgConstraint] = Field(default_factory=list)


class Remediation(BaseModel):
    """Actionable hybrid-PQC remediation guidance."""

    summary: str
    hybrid_pqc_target: str
    code_example: str = ""


class Rule(BaseModel):
    """YAML-defined cryptographic detection rule."""

    id: str
    name: str
    language: Language
    library: str
    algorithm: str
    primitive: str
    quantum_vulnerability: QuantumVulnerability
    risk_level: RiskLevel
    cwe: str = "CWE-327"
    nist_pqc_status: str = "deprecated-by-2030"
    parameter_set: str | None = None
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None
    crypto_functions: list[str] = Field(default_factory=list)
    description: str
    match: RuleMatch
    remediation: Remediation


class RuleFile(BaseModel):
    """Top-level structure of a YAML rule file."""

    rules: list[Rule]


class ParsedCall(BaseModel):
    """A function or method call extracted from a Tree-sitter CST."""

    callee: str
    resolved_callee: str
    args: list[str | int | float | bool | None] = Field(default_factory=list)
    kwargs: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    snippet: str


class ParsedSymbol(BaseModel):
    """An identifier or attribute reference extracted from a Tree-sitter CST."""

    symbol: str
    resolved_symbol: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    snippet: str


class ParsedFile(BaseModel):
    """Structured AST extraction result for a single source file."""

    path: str
    language: Language
    imports: dict[str, str] = Field(default_factory=dict)
    imported_modules: list[str] = Field(default_factory=list)
    calls: list[ParsedCall] = Field(default_factory=list)
    symbols: list[ParsedSymbol] = Field(default_factory=list)


class CertificateMetadata(BaseModel):
    """X.509 certificate metadata extracted via cryptography.x509."""

    subject: str
    issuer: str
    serial_number: str
    not_valid_before: str
    not_valid_after: str
    is_expired: bool
    public_key_algorithm: str
    key_size: int | None = None
    signature_hash_algorithm: str | None = None
    fingerprint_sha256: str


class Finding(BaseModel):
    """A single cryptographic asset or vulnerability finding."""

    rule_id: str
    rule_name: str
    file_path: str
    language: Language
    asset_type: AssetType = AssetType.ALGORITHM
    algorithm: str
    primitive: str
    parameter_set: str | None = None
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None
    crypto_functions: list[str] = Field(default_factory=list)
    quantum_vulnerability: QuantumVulnerability
    risk_level: RiskLevel
    cwe: str
    nist_pqc_status: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    snippet: str
    matched_symbol: str
    description: str
    remediation: Remediation
    certificate: CertificateMetadata | None = None


class ScanResult(BaseModel):
    """Aggregated result of scanning a file or directory."""

    target_path: str
    files_scanned: int
    findings: list[Finding] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.INFO)

    def should_fail(self, fail_on: str) -> bool:
        """Return True if findings exceed the configured failure threshold."""
        threshold = fail_on.lower().strip()
        if threshold == "none":
            return False
        if threshold == "critical":
            return self.critical_count > 0
        if threshold == "warning":
            return (self.critical_count + self.warning_count) > 0
        raise ValueError(f"Unsupported fail_on threshold: {fail_on}")
