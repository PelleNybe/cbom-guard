# Contributing to `cbom-guard`

Thank you for your interest in improving `cbom-guard`!

## Development Setup

```bash
git clone https://github.com/CoraxCoLAB/cbom-guard.git
cd cbom-guard
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality Gates

Before opening a Pull Request, ensure all checks pass:

```bash
ruff check .
mypy src tests
pytest
```

## Adding New Rules

See [docs/RULE_AUTHORING_GUIDE.md](docs/RULE_AUTHORING_GUIDE.md) for the YAML rule schema and add corresponding positive and negative test fixtures under `tests/fixtures/`.
