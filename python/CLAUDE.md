# Attesta — Python SDK

## Stack

- Python 3.11+
- Build: hatchling
- Lint: ruff (E, F, I, N, UP, B), line length 120
- Type check: mypy strict
- Test: pytest with asyncio_mode = "auto"
- Zero runtime dependencies (stdlib only)

## Structure

```
python/
├── src/attesta/
│   ├── __init__.py          # Public API: Attesta class, from_config()
│   ├── core/
│   │   ├── types.py         # Enums, dataclasses, protocols (zero internal deps)
│   │   ├── gate.py          # CoreAttesta orchestrator + @gate decorator
│   │   ├── risk.py          # Risk scorers (Default, Composite, Max, Fixed)
│   │   ├── trust.py         # Bayesian adaptive trust engine
│   │   └── audit.py         # SHA-256 hash-chained JSONL audit logger
│   ├── challenges/          # confirm, quiz, teach_back, multi_party
│   ├── renderers/           # terminal (rich), web (async HTTP)
│   ├── integrations/        # langchain, openai, crewai, anthropic, mcp
│   ├── domains/             # Domain profiles + presets (devops, data_pipeline)
│   ├── config/              # YAML/JSON config loader → Policy dataclass
│   ├── cli/                 # CLI: init, audit, trust, mcp-wrap
│   ├── environment.py       # Environment detection
│   ├── events.py            # Event bus
│   ├── exporters.py         # CSV/JSON export
│   └── webhooks.py          # Webhook dispatch
├── tests/                   # 18 test files
└── pyproject.toml
```

## Commands

```bash
# Install (from repo root)
cd python && pip install -e ".[dev,yaml,terminal]"

# Run all tests (use the project venv)
.venv/bin/python -m pytest python/tests/ -q

# Run a single test file
.venv/bin/python -m pytest python/tests/test_gate.py -q

# Run a single test function
.venv/bin/python -m pytest python/tests/test_gate.py::TestGateDecorator::test_basic_gate -q

# Lint
cd python && ruff check src tests

# Type check
cd python && mypy src/attesta
```

## Conventions

- All public API goes through `__init__.py`
- All extensibility uses `typing.Protocol` (structural subtyping, no ABC)
- Type hints on all public functions and methods
- Google-style docstrings on public APIs
- `ActionContext.description` is a **property** (not a constructor param) — use `function_doc=` for docstring text
- Zero required deps — all extras (rich, pyyaml, framework SDKs) are optional
- File permissions `0o600` for audit and trust files
- `asyncio.wait_for()` for approval timeout
- HTML escaping via `_esc()` in web renderer
- Terminal input wrapped in `try/except (EOFError, KeyboardInterrupt)`

## What NOT To Do

- Do not add runtime dependencies to the core
- Do not modify pyproject.toml without asking
- Do not change the hash chain format (backwards-compatibility contract)
- Do not change the JSONL audit field order
- Do not reference OSS_SCOPE.md in any public-facing content
