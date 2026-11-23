# `cbom-guard` Architecture

`cbom-guard` is a multi-language static analysis and cryptographic asset inventory engine built for Post-Quantum Cryptography (PQC) readiness.

## High-Level Pipeline

1. **Discovery (`scanner/workspace.py`):** Recursively traverses the target path, skipping build/cache/VCS directories, and dispatches source files to `ASTParser` and X.509 certificates (`.pem`, `.crt`, `.cer`, `.der`) to `cert_scanner.py`.
2. **Tree-sitter AST Parsing (`scanner/ast_parser.py`):**
   - Uses native `tree-sitter` grammars for Python, JavaScript/TypeScript, C, C++, and Go.
   - Builds a per-file import/alias symbol table (e.g., `import rsa as r`, `from Crypto.Cipher import DES3`, `import crypto from "node:crypto"`).
   - Extracts call expressions (`ParsedCall`) with resolved callee names, positional arguments, keyword/object-literal arguments, and exact 1-based line/column spans.
   - Ignores comments and non-call string literals, eliminating regex false positives.
3. **Rule Evaluation (`scanner/rule_engine.py`):**
   - Validates YAML rules via Pydantic v2 (`models.py`).
   - Enforces `match.imports` context checks before matching `callees` or `symbols`.
   - Evaluates `arg_constraints` (`lt`, `lte`, `gt`, `gte`, `eq`, `neq`, `in`, `not_in`, `regex`) on parsed argument values.
4. **X.509 Inspection (`scanner/cert_scanner.py`):**
   - Parses PEM/DER certificates via `cryptography.x509`, extracting public key algorithm, key size, signature hash, validity dates, and SHA-256 fingerprint.
5. **Reporters (`reporters/`):**
   - `cyclonedx.py`: Exports schema-validated CycloneDX 1.6 CBOM JSON (`cryptoProperties`, `algorithmProperties`, `certificateProperties`, `evidence.occurrences`, and `vulnerabilities`).
   - `sarif.py`: Exports SARIF 2.1.0 JSON with CWE tags, security severity, snippets, and markdown remediation for GitHub Code Scanning.
   - `terminal.py`: Renders Rich tables and enforces `--fail-on` exit codes.
   - `github_pr.py`: Parses PR unified diff hunks and posts deduplicated inline review comments with hybrid-PQC migration snippets.
