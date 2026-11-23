# GitHub Action Guide

Integrate `cbom-guard` into any GitHub repository in 5 lines of YAML to automate Post-Quantum Cryptography scanning, CycloneDX 1.6 CBOM artifact generation, SARIF Security tab uploads, and inline PR remediation comments.

## Minimal Workflow

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

## Inputs

| Input | Default | Description |
| :--- | :--- | :--- |
| `path` | `.` | Target file or directory to scan |
| `fail-on` | `critical` | Exit non-zero threshold (`critical`, `warning`, `none`) |
| `cbom-output` | `cbom.json` | Output path for CycloneDX 1.6 CBOM JSON |
| `sarif-output` | `cbom-guard.sarif` | Output path for SARIF 2.1.0 JSON |
| `comment-pr` | `true` | Post deduplicated inline review comments on PRs |
| `upload-sarif` | `true` | Upload SARIF to GitHub Code Scanning |
| `github-token` | `${{ github.token }}` | Token used for PR review comments |

## Outputs

- `cbom-path`: Path to the generated `cbom.json`.
- `sarif-path`: Path to the generated `cbom-guard.sarif`.
- `critical-count`: Count of Shor-vulnerable (`critical`) findings.
- `warning-count`: Count of Grover/legacy (`warning`) findings.
