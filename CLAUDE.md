# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Attesta** is an open-core Human-in-the-Loop (HITL) approval framework for AI agents. It scores action risk and selects verification challenges proportional to that risk — from auto-approving safe reads to requiring multi-party sign-off for irreversible operations. The OSS layer (this repo) covers the proof pipeline; the proprietary layer (not here) covers dashboards, analytics, and fleet management.

## Build and Test Commands

### Python

```bash
# Install (from repo root)
cd python && pip install -e ".[dev,yaml,terminal]"

# Run all tests (use the project venv — system Python may be too old)
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

Requires Python 3.11+ (venv at `.venv/` uses 3.11 or 3.12). asyncio_mode is "auto" in pyproject.toml.

### TypeScript

```bash
cd typescript
npm install
npm run typecheck   # tsc --noEmit
npm run build       # compile ESM + CJS
npm test            # node --test
```

Requires Node.js 18+.

### No-code packages

```bash
PYTHONPATH=python/src pytest packages/langflow-attesta/tests -q
PYTHONPATH=python/src pytest packages/dify-attesta/tests -q
```

### Docs (Mintlify)

```bash
npx mintlify@latest dev   # from repo root; requires Node <25 (use nvm use 22)
```

## Architecture

### Two Attesta Classes

There are two `Attesta` classes — understanding the distinction is critical:

1. **`attesta/__init__.py:Attesta`** — The public-facing entry point. Holds shared config (policy, scorer, renderer, audit logger, trust engine). Creates and caches a `CoreAttesta` instance on first `evaluate()` call. This is what users import and configure. Has `from_config()` for YAML loading and a `.gate()` decorator factory.

2. **`attesta/core/gate.py:Attesta` (aliased as `CoreAttesta`)** — The internal orchestrator that runs the actual pipeline: risk scoring → challenge selection → verification → audit logging. Stateful (tracks novelty). The `@gate` module-level decorator creates a `CoreAttesta` per decorated function.

### Request Flow

```
@gate decorator or Attesta.evaluate(ctx)
  → CoreAttesta.evaluate(ActionContext)
    → RiskScorer.score(ctx) → float [0,1]
    → TrustEngine.effective_risk() (if configured) → adjusted score
    → RiskLevel.from_score() → LOW/MEDIUM/HIGH/CRITICAL
    → challenge_map[risk_level] → ChallengeType
    → asyncio.wait_for(Renderer.render_challenge(...), timeout)
    → AuditLogger.log(entry)
    → ApprovalResult
```

### Key Modules

- **`core/types.py`** — All enums, dataclasses, and protocols. Zero internal deps. Import-safe from anywhere.
- **`core/risk.py`** — `DefaultRiskScorer` (5-factor weighted), `CompositeRiskScorer`, `MaxRiskScorer`, `FixedRiskScorer`.
- **`core/trust.py`** — Bayesian-inspired adaptive trust. Exponential decay, per-agent/per-domain. Persists to JSON.
- **`core/audit.py`** — SHA-256 hash-chained JSONL. `verify_chain()` detects tampering.
- **`challenges/`** — `confirm.py`, `quiz.py`, `teach_back.py`, `multi_party.py`. Each challenge is instantiated by the renderer.
- **`renderers/`** — `terminal.py` (rich), `web.py` (async HTTP). Default renderer auto-approves in non-TTY Python, denies in TS.
- **`integrations/`** — LangChain, OpenAI Agents SDK, CrewAI, Anthropic, MCP. Each wraps `Attesta.evaluate()`.
- **`domains/`** — `DomainProfile`, `DomainRiskScorer`, presets (`devops`, `data_pipeline`).
- **`config/loader.py`** — Parses YAML into a `Policy` dataclass. Supports structured (`policy:`, `risk:`, `trust:`) and legacy flat format.

### TypeScript SDK

Mirrors the Python SDK at `typescript/src/`. Dual ESM/CJS output. Key difference: non-TTY defaults to DENY (Python defaults to auto-approve).

## Critical Gotchas

1. **`ActionContext.description` is a property**, not a constructor param. It's derived from `function_name` + `args`. To set docstring text, use `function_doc=`.
2. **System Python vs venv**: Project venv is at `.venv/`. System Python may be 3.9. Always use `.venv/bin/python`.
3. **Zero-dependency core**: Python core has zero required deps. All extras (`rich`, `pyyaml`, framework SDKs) are optional. Don't add required deps.
4. **Hash chain format**: JSONL audit format is a backwards-compatibility contract. Don't change hashing algorithm or field order.
5. **OSS_SCOPE.md**: Internal strategy doc, gitignored. Don't commit or reference in public-facing content.
6. **`risk_override` hints**: Blocked by default (`allow_hint_override=False`). Trusted overrides use the `TRUSTED_RISK_OVERRIDE_METADATA_KEY` metadata path instead.

## Code Conventions

- **Python**: ruff (`E, F, I, N, UP, B`), mypy strict, line length 120, target 3.11.
- **TypeScript**: strict mode, dual ESM/CJS.
- **Security**: HTML escaping via `_esc()`/`escapeHtml()`. CSRF tokens on all web forms. `execFile()` not `exec()`. File permissions `0o600` for audit/trust files. `asyncio.wait_for()` for approval timeout. All terminal input wrapped in `try/except (EOFError, KeyboardInterrupt)`.
- **Protocols**: All extensibility uses `typing.Protocol` (structural subtyping). No ABC inheritance required.

## CI

`.github/workflows/ci.yaml`: Python tests (3.12), TS typecheck + build + test, ruff lint, mypy, release boundary check, dependency review, docs link check.
