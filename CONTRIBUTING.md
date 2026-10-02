# Contributing

AegisForge is commercial, proprietary software. Contributions are welcome
from the community, but note the licensing terms before you start.

## License terms for contributors

- AegisForge is **not** open source. It is proprietary software with a
  7-day free trial (see [LICENSE](LICENSE)).
- By submitting a pull request or patch, you agree that your
  contribution becomes the property of the copyright holder
  (Pouya Shini Karim) and may be incorporated into the commercial
  product under its proprietary license.
- Do not submit code you do not have the rights to contribute.

## Development setup

```bash
git clone https://github.com/REV3R5ED/AegisForge.git
cd AegisForge
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates (all must pass)

```bash
pytest                                  # full suite; coverage must stay >= 80%
ruff check . && ruff format --check .
mypy src
```

## Conventions

- Stdlib only, zero dependencies. Python 3.10–3.13.
- Never use `shell=True`; never use TOML for load-bearing config
  (`tomllib` is 3.11+ — config files are JSON).
- Validate all external input at the boundary (`network/validation.py`).
- New modules register with `core.plugins` and emit normalized
  `core.events.Event`s and `core.findings.Finding`s.
- Human-readable output by default; `--json`/`--csv` must keep working.
- Exit codes: 0 ok, 1 findings, 2 error — document any new semantics.
- Mock subprocess and network calls in tests; no real network in CI.
