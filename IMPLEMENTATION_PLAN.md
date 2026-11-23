# `cbom-guard` — Comprehensive Architecture & Implementation Plan

**Organization:** Corax CoLAB  
**Target Standard:** CycloneDX 1.6 (CBOM), SARIF 2.1.0, NIST PQC (FIPS 203/204/205), NSA CNSA 2.0  
**Language & Runtime:** Python 3.11+ (strictly typed with `mypy`)

---

## 1. Tree-sitter AST Query & Traversal Architecture

### Why AST Parsing Eliminates Regex False Positives
Regex-based cryptography scanners fail in real-world codebases because they cannot distinguish executable cryptographic calls from comments, docstrings, string literals, variable names, or unrelated APIs. For example:
- `# TODO: replace rsa.generate_private_key with ML-KEM` -> comment, not executable code.
- `logger.info("Using SHA1 for legacy checksum display only")` -> string literal, not a hash call.
- `def md5_enabled(): return False` -> identifier name, not a `hashlib.md5()` invocation.
- `rsa.generate_private_key(public_exponent=65537, key_size=4096)` vs `key_size=1024` -> regex cannot reliably resolve keyword arguments, multi-line calls, or import aliases (`from cryptography.hazmat.primitives.asymmetric import rsa as r`).

### Multi-Language Tree-sitter Engine (`src/cbom_guard/scanner/ast_parser.py`)
`cbom-guard` uses `tree-sitter` (>=0.22+) with official native language grammars (`tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-c`, `tree-sitter-cpp`, `tree-sitter-go`):
1. **Language Dispatch & File Filtering:** Maps file extensions (`.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.cxx`, `.go`) to their compiled `tree_sitter.Language` and `Parser`.
2. **Import & Alias Resolution:**
   - **Python:** Walks `import_statement` and `import_from_statement` nodes to build a per-file symbol table mapping local aliases (e.g., `r -> cryptography.hazmat.primitives.asymmetric.rsa`, `AES -> Crypto.Cipher.AES`, `hl -> hashlib`) to canonical module/symbol paths.
   - **JavaScript/TypeScript:** Walks `import_statement` and `call_expression` (`require("...")`) to track bindings (`crypto`, `jose`, `jsonwebtoken`, `node:crypto`).
   - **Go:** Walks `import_spec` nodes to resolve package aliases (e.g., `crypto/rsa`, `crypto/ecdsa`, `crypto/md5`, `crypto/sha1`, `crypto/des`).
   - **C/C++:** Walks `preproc_include` (`<openssl/rsa.h>`, `<openssl/evp.h>`, `<sodium.h>`) to establish cryptographic context.
3. **Structured Call & Attribute Extraction:**
   - Extracts every call expression (`call` in Python, `call_expression` in JS/TS/C/C++/Go) along with:
     - Resolved callee path (e.g., `hashlib.md5`, `EVP_PKEY_RSA`, `crypto.createHash`)
     - Positional arguments (parsed literal values & identifiers)
     - Keyword/named arguments (e.g., `key_size=2048`, `hash_algorithm=hashes.SHA256`)
     - Exact 1-based start/end line and column coordinates + source snippet
   - **Comment & String Exclusion:** Because Tree-sitter produces a concrete syntax tree (CST), `comment` and `string` nodes outside of call argument positions are never treated as call sites.
4. **AST Pattern & Constraint Evaluation (`src/cbom_guard/scanner/rule_engine.py`):**
   - Evaluates YAML rules against extracted AST call/symbol records:
     - `callee_patterns` / `symbol_patterns`: Exact canonical or suffix match on resolved imports + call chains.
     - `arg_constraints`: Evaluates positional or keyword argument values (e.g., `key_size < 2048`, `algorithm in ["md5", "sha1", "des-ede3"]`, `curve == "SECP256R1"`).
     - `context_requires_import`: Ensures a rule only fires when the relevant cryptographic library is actually imported in the file, eliminating collisions with identically named user functions.

---

## 2. YAML Rule Schema Design

Each language/domain has a dedicated rule file under `src/cbom_guard/rules/` (`python.yaml`, `openssl.yaml`, `javascript.yaml`, `go.yaml`).

### Schema Structure (Validated by Pydantic v2 in `models.py`)
```yaml
rules:
  - id: PY-CRYPTO-001
    name: RSA Key Generation (Shor-Vulnerable)
    language: python
    library: cryptography
    algorithm: RSA
    primitive: pke # pke | signature | key-agreement | hash | block-cipher | mac | kdf
    quantum_vulnerability: shor # shor | grover | none
    risk_level: critical # critical | warning | info
    cwe: CWE-327
    nist_pqc_status: deprecated-by-2030 # CNSA 2.0 / NIST IR 8547
    description: >
      RSA key generation relies on integer factorization, which is broken in
      polynomial time by Shor's algorithm on a cryptographically relevant quantum computer.
    match:
      imports:
        - cryptography.hazmat.primitives.asymmetric.rsa
      callees:
        - cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key
        - rsa.generate_private_key
      arg_constraints: # Optional
        - param: key_size
          op: lte # eq | neq | lt | lte | gt | gte | in | regex
          value: 4096
    remediation:
      summary: Migrate key encapsulation to ML-KEM-768 (FIPS 203) or hybrid X25519+ML-KEM-768, and signatures to ML-DSA-65 (FIPS 204).
      hybrid_pqc_target: X25519 + ML-KEM-768 / ML-DSA-65
      code_example: |
        # Replace RSA key exchange with hybrid X25519 + ML-KEM-768 via liboqs-python
        import oqs
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            public_key = kem.generate_keypair()
```

### NIST PQC Vulnerability Classification
| Quantum Threat | Algorithms | `risk_level` | `quantum_vulnerability` | Actionable Guidance |
| :--- | :--- | :--- | :--- | :--- |
| **Shor's Algorithm** | RSA, ECC/ECDSA, ECDH, DSA, DH, Ed25519, X25519 (standalone) | `critical` | `shor` | Broken by CRQC. Migrate to ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), or Hybrid PQC. |
| **Grover's Algorithm** | AES-128, 3DES, RC4, MD5, SHA-1, SHA-256 (for 128-bit collision resistance notes) | `warning` (or `critical` for broken MD5/SHA-1/RC4/DES) | `grover` | Effective security halved (AES-128 -> 64-bit) or classically broken (MD5/SHA-1). Upgrade to AES-256 / SHA-384 / SHA-512 / SHA-3. |
| **Quantum-Safe / PQC** | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384, SHA-512, ChaCha20-Poly1305 | `info` | `none` | Compliant with NIST PQC & CNSA 2.0. Inventoried in CBOM without failing CI. |

---

## 3. CycloneDX 1.6 CBOM & SARIF 2.1.0 Mapping

### CycloneDX 1.6 Cryptographic Bill of Materials (`src/cbom_guard/reporters/cyclonedx.py`)
Generated using `cyclonedx-python-lib` (targeting SchemaVersion `1.6`) and validated against the official CycloneDX 1.6 JSON schema:
- **Component Type:** `ComponentType.CRYPTOGRAPHIC_ASSET` (`"type": "cryptographic-asset"`).
- **Evidence / Occurrences:** Each finding's file path, line number, and symbol name are mapped to `evidence.occurrences` (`bom-ref` linked).
- **`cryptoProperties`:**
  - `assetType`: `"algorithm"` for code findings, `"certificate"` for X.509 certificates.
  - `algorithmProperties`:
    - `primitive`: mapped to CycloneDX enum (`pke`, `signature`, `key-agreement`, `hash`, `block-cipher`, `stream-cipher`, `ae`, `kdf`, `mac`).
    - `parameterSetIdentifier`: e.g., `"2048"` for RSA-2048, `"P-256"` for ECDSA P-256, `"256"` for AES-256.
    - `classicalSecurityLevel`: computed bit security (e.g., `112` for RSA-2048, `128` for P-256).
    - `nistQuantumSecurityLevel`: `0` for Shor-vulnerable or classically broken algorithms; `1`/`3`/`5` for Grover-affected or PQC algorithms.
    - `cryptoFunctions`: e.g., `["keygen"]`, `["sign", "verify"]`, `["digest"]`, `["encrypt", "decrypt"]`.
  - `certificateProperties` (for X.509 `.pem`/`.crt`/`.cer`/`.der` files):
    - `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `subjectPublicKeyRef`, `certificateFormat` (`"X.509"`).
- **Vulnerabilities / Annotations:** Custom `properties` (`cbom-guard:quantum-vulnerability`, `cbom-guard:risk-level`, `cbom-guard:remediation`) plus CycloneDX `vulnerabilities` entries for Critical/Warning findings with CWE references.

### SARIF 2.1.0 (`src/cbom_guard/reporters/sarif.py`)
- Validated against the official SARIF 2.1.0 schema (`https://json.schemastore.org/sarif-2.1.0.json`).
- `runs[0].tool.driver`: `name: "cbom-guard"`, `informationUri`, `rules` array with `id`, `name`, `shortDescription`, `fullDescription`, `help` (markdown remediation), and `properties.tags` (`["security", "cryptography", "post-quantum", "CWE-327"]`).
- `runs[0].results`: `ruleId`, `level` (`error` for `critical`, `warning` for `warning`, `note` for `info`), `message.text`, and `locations[0].physicalLocation` with `artifactLocation.uri`, `region.startLine`, `region.startColumn`, `region.endLine`, `region.endColumn`, and `region.snippet.text`.

---

## 4. GitHub Action & PR Inline Review Commenting

### GitHub Action (`action.yml`)
A composite GitHub Action allowing any repository to integrate `cbom-guard` in 5 lines of YAML:
- Inputs: `path` (default `.`), `fail-on` (`critical|warning|none`, default `critical`), `cbom-output` (default `cbom.json`), `sarif-output` (default `cbom-guard.sarif`), `comment-pr` (`true|false`, default `true`), `github-token`.
- Outputs: `cbom-path`, `sarif-path`, `critical-count`, `warning-count`.
- Execution flow:
  1. Sets up Python 3.12 and installs `cbom-guard`.
  2. Runs `cbom-guard scan` producing terminal output, CycloneDX 1.6 `cbom.json`, and `cbom-guard.sarif`.
  3. If running in a `pull_request` event and `comment-pr: true`, invokes `cbom-guard pr-comment` to post inline review comments.
  4. Uploads `cbom.json` as an artifact and (if enabled) uploads `cbom-guard.sarif` via `github/codeql-action/upload-sarif`.

### PR Inline Review Comment Engine (`src/cbom_guard/reporters/github_pr.py`)
- Uses `httpx` against the GitHub REST API (`https://api.github.com`):
  1. Fetches PR metadata (`GET /repos/{owner}/{repo}/pulls/{pull_number}`) to get `head.sha`.
  2. Fetches PR changed files and diff hunks (`GET /repos/{owner}/{repo}/pulls/{pull_number}/files`) and parses `@@ -a,b +c,d @@` unified diff hunk ranges so comments are only posted on lines present in the PR diff.
  3. Fetches existing review comments (`GET /repos/{owner}/{repo}/pulls/{pull_number}/comments`) and deduplicates using a hidden marker (`<!-- cbom-guard:rule={rule_id}:line={line} -->`) so re-runs never spam duplicate comments.
  4. Posts a single batch PR review (`POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews`) with inline comments containing the quantum risk classification, CWE, and concrete hybrid-PQC replacement code snippet.

---

## 5. Milestone Breakdown & Verification Criteria

### Phase 1 — AST Scanner for Python (MVP)
- **Deliverables:** `pyproject.toml`, `LICENSE`, `models.py`, `scanner/ast_parser.py`, `scanner/rule_engine.py`, `rules/python.yaml` (>=15 rules), `tests/fixtures/python/` (vulnerable + safe fixtures), `tests/test_python_scanner.py`.
- **Verification:** `pytest` passes 100% on Python fixtures with exact line/column assertions and 0 false positives on comments, strings, and safe PQC/AES-256/SHA-384 code. `ruff` and `mypy` pass with 0 errors.

### Phase 2 — CBOM & SARIF Reporting & CLI
- **Deliverables:** `reporters/cyclonedx.py`, `reporters/sarif.py`, `reporters/terminal.py`, `cli.py` (`scan`, `cbom`, `sarif`, `list-rules`).
- **Verification:** Generated `cbom.json` validates against CycloneDX 1.6 JSON schema; generated `cbom-guard.sarif` validates against SARIF 2.1.0 JSON schema; `--fail-on` exit codes verified via CLI tests.

### Phase 3 — GitHub Action & Automated PR Remediation
- **Deliverables:** `reporters/github_pr.py`, `cli.py` (`pr-comment`), `action.yml`, `.github/workflows/ci.yml`, `tests/test_github_pr.py` (testing diff hunk parsing, deduplication, and payload formatting with `httpx.MockTransport`).
- **Verification:** `pr-comment` dry-run and mock transport tests pass; `action.yml` syntax and inputs/outputs verified.

### Phase 4 — Multi-Language Support, Certificate Scanning & Documentation
- **Deliverables:** `rules/openssl.yaml` (C/C++), `rules/go.yaml` (Go), `rules/javascript.yaml` (JS/TS), `scanner/cert_scanner.py` (`.pem`/`.crt`/`.cer`/`.der` X.509 parsing), fixtures & tests for C/C++, Go, JS, and real generated X.509 test certificates, plus `docs/` (`ARCHITECTURE.md`, `RULE_AUTHORING_GUIDE.md`, `GITHUB_ACTION_GUIDE.md`, `USER_MANUAL.md`), `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and marketing-grade `README.md`.
- **Verification:** Full `ruff check .`, `mypy src tests`, and `pytest` pass 100% across all languages, certificates, CBOM, SARIF, CLI, and PR commenter.
