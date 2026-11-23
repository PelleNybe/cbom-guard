# Rule Authoring Guide

Rules are defined in YAML files under `src/cbom_guard/rules/` (or any custom directory passed via `--rules-dir`).

## Rule Schema

```yaml
rules:
  - id: PY-CRYPTO-001
    name: RSA Key Generation (cryptography)
    language: python          # python | javascript | c | cpp | go
    library: cryptography
    algorithm: RSA
    primitive: pke            # pke | signature | key-agreement | hash | block-cipher | ae | kdf | mac
    parameter_set: "2048"
    classical_security_level: 112
    nist_quantum_security_level: 0   # 0-6 per CycloneDX 1.6
    crypto_functions: ["keygen"]
    quantum_vulnerability: shor      # shor | grover | none
    risk_level: critical             # critical | warning | info
    cwe: CWE-327
    nist_pqc_status: deprecated-by-2030
    description: >
      Human-readable explanation of the classical and quantum risk.
    match:
      imports:
        - cryptography.hazmat.primitives.asymmetric.rsa
      callees:
        - cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key
      arg_constraints:
        - param: key_size
          op: lt
          value: 2048
    remediation:
      summary: Migrate to ML-KEM-768 (FIPS 203) or ML-DSA-65 (FIPS 204).
      hybrid_pqc_target: X25519 + ML-KEM-768
      code_example: |
        import oqs
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            public_key = kem.generate_keypair()
```

## Supported `arg_constraints` Operators
- `eq`, `neq`: Exact equality / inequality.
- `lt`, `lte`, `gt`, `gte`: Numeric comparison on integer/float literals.
- `in`, `not_in`: Membership in a list of strings or numbers.
- `regex`: Regular expression match against stringified argument value.
- `param`: Either a keyword argument name (e.g., `key_size`, `algorithm`) or a 0-based positional argument index (e.g., `0`).
