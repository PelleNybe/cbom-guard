# Changelog

All notable changes to `cbom-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-23

### Added
- Multi-language Tree-sitter AST scanner (`python`, `javascript`/`typescript`, `c`, `cpp`, `go`) with import/alias resolution and argument constraint evaluation.
- 34 built-in YAML detection rules across `python.yaml` (18 rules), `openssl.yaml` (7 rules), `go.yaml` (5 rules), and `javascript.yaml` (4 rules).
- Real X.509 certificate scanner (`.pem`, `.crt`, `.cer`, `.der`) via `cryptography.x509`.
- Standards-compliant CycloneDX 1.6 CBOM exporter (`cyclonedx-python-lib`) with strict JSON schema validation.
- Standards-compliant SARIF 2.1.0 exporter for GitHub Code Scanning.
- Rich terminal reporter with configurable `--fail-on` thresholds (`critical`, `warning`, `none`).
- GitHub PR inline review comment engine (`httpx`) with unified diff hunk filtering and marker-based deduplication.
- Composite GitHub Action (`action.yml`) and CI workflow (`.github/workflows/ci.yml`).
- Full documentation suite in `docs/`.
