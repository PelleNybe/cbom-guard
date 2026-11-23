# `cbom-guard` User Manual

## Installation

```bash
pip install cbom-guard
# or with uv:
uv tool install cbom-guard
```

## CLI Commands

### 1. `cbom-guard scan <path>`
Scans source code (Python, C/C++, Go, JavaScript/TypeScript) and X.509 certificates (`.pem`, `.crt`, `.cer`, `.der`), prints a Rich summary table, and optionally exports CBOM and SARIF:

```bash
cbom-guard scan ./src \
  --cbom-out cbom.json \
  --sarif-out cbom-guard.sarif \
  --fail-on critical
```

### 2. `cbom-guard cbom <path>`
Generates and schema-validates a CycloneDX 1.6 Cryptographic Bill of Materials:

```bash
cbom-guard cbom . --output cbom.json --validate
```

### 3. `cbom-guard sarif <path>`
Generates a SARIF 2.1.0 report for GitHub Code Scanning:

```bash
cbom-guard sarif . --output cbom-guard.sarif
```

### 4. `cbom-guard pr-comment <path>`
Posts deduplicated inline review comments on changed lines of a GitHub Pull Request:

```bash
GITHUB_TOKEN=ghp_... cbom-guard pr-comment . --repo owner/repo --pr 42
```

### 5. `cbom-guard list-rules`
Displays all loaded detection rules, filterable by language:

```bash
cbom-guard list-rules --language python
```
