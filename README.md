<div align="center">

# 🛡️ `cbom-guard`

**Automated Post-Quantum Cryptography (PQC) Code Scanner, CycloneDX 1.6 CBOM Generator, SARIF Exporter & GitHub PR Remediation Bot**

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![CI Status](https://img.shields.io/badge/CI-passing-brightgreen.svg)](.github/workflows/ci.yml)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-0A66C2.svg)](https://cyclonedx.org/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](https://sarifweb.oasis-open.org/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Ready-2088FF.svg)](action.yml)

</div>

---

## 🚨 Why `cbom-guard`? The Quantum Migration Imperative

**"Harvest Now, Decrypt Later"** is already underway. Adversaries are capturing encrypted traffic today to decrypt it once cryptographically relevant quantum computers (CRQCs) arrive.

Global mandates are locking in hard deadlines:
- 🇺🇸 **NIST PQC Standards (FIPS 203, 204, 205):** Standardized **ML-KEM** (Kyber), **ML-DSA** (Dilithium), and **SLH-DSA** (SPHINCS+) to replace RSA, ECC, DSA, and DH.
- 🛡️ **NSA CNSA 2.0:** Requires software, firmware, and networking stacks to transition to quantum-resistant cryptography (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87) by **2030**.
- 🇪🇺 **EU PQC Roadmap:** Calls on Member States and critical infrastructure operators to inventory cryptographic assets via **Cryptographic Bills of Materials (CBOM)** and begin hybrid PQC migration immediately.

Regex-based scanners drown engineering teams in false positives from comments, log strings, and docstrings. **`cbom-guard`** uses **Tree-sitter AST parsing** with full import/alias resolution and argument-constraint evaluation to pinpoint real cryptographic call sites across **Python, C/C++, Go, JavaScript/TypeScript**, and **X.509 certificates** — then automatically generates **CycloneDX 1.6 CBOMs**, **SARIF 2.1.0** security alerts, and **inline GitHub PR remediation comments**.

---

## ⚙️ How It Works

```mermaid
flowchart LR
    A["📂 Source Code & X.509 Certs<br/>(Python, C/C++, Go, JS/TS, .pem/.crt)"] --> B["🌳 Tree-sitter AST Engine<br/>& cryptography.x509"]
    B --> C["📜 YAML PQC Rule Engine<br/>(Shor = Critical | Grover = Warning)"]
    C --> D["📦 CycloneDX 1.6 CBOM<br/>(cbom.json)"]
    C --> E["🔍 SARIF 2.1.0<br/>(GitHub Security Tab)"]
    C --> F["💬 GitHub PR Bot<br/>(Inline Hybrid-PQC Fixes)"]
    C --> G["🖥️ Rich Terminal CLI<br/>(--fail-on critical|warning|none)"]
```

---

## ⚡ Quickstart

### Install & Run Locally

```bash
pip install cbom-guard
# or with uv:
uv tool install cbom-guard
```

Scan a repository, generate a schema-validated CycloneDX 1.6 CBOM, and export SARIF 2.1.0:

```bash
cbom-guard scan ./src \
  --cbom-out cbom.json \
  --sarif-out cbom-guard.sarif \
  --fail-on critical
```

Inspect all loaded PQC detection rules:

```bash
cbom-guard list-rules
```

---

## 🧩 Interactive Examples & Reference

<details>
<summary>🚀 <strong>5-Line GitHub Action Workflow</strong> (CBOM Artifacts + Security Tab + Inline PR Comments)</summary>

```yaml
name: PQC Readiness
on: [push, pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  cbom-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: CoraxCoLAB/cbom-guard@v0.1.0
        with:
          fail-on: critical
```

</details>

<details>
<summary>📦 <strong>Sample CycloneDX 1.6 CBOM Output</strong> (<code>cbom.json</code>)</summary>

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "bom-ref": "cbom-asset-1-PY-CRYPTO-001",
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "cryptoFunctions": ["keygen"],
          "classicalSecurityLevel": 112,
          "nistQuantumSecurityLevel": 0
        }
      },
      "evidence": {
        "occurrences": [
          {
            "location": "src/auth/keys.py",
            "line": 18,
            "offset": 15,
            "symbol": "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key"
          }
        ]
      }
    }
  ]
}
```

</details>

<details>
<summary>📋 <strong>Supported Languages, Libraries & PQC Rule Matrix (34 Built-in Rules)</strong></summary>

| Language / Artifact | Libraries & Standards Covered | Quantum Threats Detected |
| :--- | :--- | :--- |
| **Python** (18 rules) | `cryptography`, `hashlib`, `PyCryptodome` (`Crypto.*`/`Cryptodome.*`), `ssl`, `rsa`, `ecdsa` | Shor (RSA, RSA `< 2048`, ECDSA/ECC, DSA, DH, Ed25519/X25519, TLS 1.0/1.1), Grover (3DES, DES, RC4, MD5, SHA-1), Safe (`AES-256-GCM`) |
| **C / C++** (7 rules) | OpenSSL (`<openssl/evp.h>`, `<openssl/rsa.h>`, `<openssl/ec.h>`, `<openssl/des.h>`) | Shor (`EVP_RSA_gen`, `RSA_generate_key_ex`, `EVP_EC_gen`, `EC_KEY_generate_key`), Grover (`EVP_md5`, `EVP_sha1`, `EVP_des_ede3_cbc`, `EVP_rc4`), Safe (`EVP_aes_256_gcm`) |
| **Go** (5 rules) | `crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/ed25519`, `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4` | Shor (RSA, ECDSA, ECDH, Ed25519), Grover (MD5, SHA-1, DES, 3DES, RC4) |
| **JavaScript / TypeScript** (4 rules) | `node:crypto` / `crypto`, `jsonwebtoken` | Shor (`generateKeyPair`/`generateKeyPairSync` RSA/EC/DSA, JWT `RS256`/`ES256`/`PS256`), Grover (`createHash` MD5/SHA-1, `createCipheriv` DES/3DES/RC4) |
| **X.509 Certificates** | `.pem`, `.crt`, `.cer`, `.der` via `cryptography.x509` | Shor (RSA, ECDSA, DSA, Ed25519, Ed448 public keys), Weak signature hashes (MD5, SHA-1), Expiration tracking |

</details>

---

## 📚 Documentation

- [User Manual](docs/USER_MANUAL.md)
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Rule Authoring Guide](docs/RULE_AUTHORING_GUIDE.md)
- [GitHub Action Guide](docs/GITHUB_ACTION_GUIDE.md)
- [Implementation Plan](IMPLEMENTATION_PLAN.md)
- [Changelog](CHANGELOG.md) | [Contributing](CONTRIBUTING.md) | [Security Policy](SECURITY.md)

---

## 🏆 Creators & Credits

`cbom-guard` is engineered and maintained by:

- **Organization:** [**Corax CoLAB**](https://coraxcolab.com) — *Deep Tech, Edge AI & Quantum Security Engineering*
- **Lead Developer:** **Pelle Nyberg** ([GitHub: `@PelleNybe`](https://github.com/PelleNybe))

---

## 📄 License

Distributed under the [MIT License](LICENSE).
