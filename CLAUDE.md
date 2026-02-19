# CLAUDE.md

Project context for Claude Code and AI-assisted development.

## Project Overview

**Attesta** is an open-core Human-in-the-Loop (HITL) approval framework for AI agents. It solves the "rubber-stamping problem" by scoring action risk and selecting verification challenges proportional to that risk. The OSS layer covers the proof pipeline (risk scoring, challenges, audit); the proprietary layer (not in this repo) covers operations (dashboards, analytics, fleet management).

## Repository Structure

```
attesta/
  python/             # Python SDK — PyPI: attesta
    src/attesta/      # Source (core/, challenges/, renderers/, integrations/, domains/, config/, cli/)
    tests/            # pytest test suite (503+ tests)
    pyproject.toml    # Hatchling build, zero required deps
  typescript/         # TypeScript SDK — npm: @kyberon/attesta
    src/              # Source (mirrors Python: gate, risk, trust, audit, challenges, renderers, integrations)
    tests/            # Node test runner
    package.json
  packages/           # No-code platform integrations
    dify-attesta/     # Dify plugin
    flowise-attesta/  # Flowise community node
    langflow-attesta/ # Langflow component
    n8n-nodes-attesta/# n8n community node
  docs/               # Mintlify documentation site (64 .mdx files)
  scripts/            # Benchmarks, release tooling, SBOM generation
  examples/           # Working example apps (LangChain, OpenAI Agents, Vercel AI)
```

## Development Setup

### Python (primary SDK)

```bash
cd python
pip install -e ".[dev,yaml,terminal]"
```

Requires Python 3.11+ (venv at `.venv/` uses 3.11 or 3.12).

### TypeScript

```bash
cd typescript
npm install
npm run build
```

Requires Node.js 18+. Use Node v22 (not v25) for docs dev server.

### Documentation

```bash
npx mintlify@latest dev   # from repo root; runs on port 3000+
```

## Running Tests

### Python

```bash
# From repo root — use the project venv
.venv/bin/python -m pytest python/tests/ -q

# Or if inside the venv
cd python && pytest tests/ -q
```

All 503+ tests should pass. asyncio_mode is set to "auto" in pyproject.toml.

### TypeScript

```bash
cd typescript
npm run typecheck   # tsc --noEmit
npm run build       # compile ESM + CJS
npm test            # node --test
```

### No-code packages

```bash
PYTHONPATH=python/src pytest packages/langflow-attesta/tests -q
PYTHONPATH=python/src pytest packages/dify-attesta/tests -q
```

## Key Architecture Concepts

- **`@gate` decorator** (Python) / `gate()` wrapper (TS): Entry point. Wraps any function with risk-scored HITL approval.
- **`Attesta` class**: Shared config holder — risk scorer, renderer, audit logger, trust engine, challenge map, policy.
- **Risk pipeline**: 5-factor scoring (function name 30%, arguments 25%, docstring 20%, hints 15%, novelty 10%) with environment multiplier.
- **Challenge types**: AUTO_APPROVE, CONFIRM, QUIZ, TEACH_BACK, MULTI_PARTY — selected by risk level.
- **TrustEngine**: Bayesian-inspired adaptive trust with exponential decay, per-agent/per-domain tracking.
- **AuditLogger**: SHA-256 hash-chained JSONL; `verify_chain()` detects tampering.
- **Domain profiles**: Industry-specific risk patterns, sensitive terms, escalation rules (presets: `devops`, `data_pipeline`).
- **Modes**: `enforce` (default), `shadow` (log but don't block), `audit_only` (log only, no challenges).

## Important Types (Python)

- `ActionContext` — dataclass; `description` is a `@property` (derived from `function_name` + `args`), NOT a constructor param. Use `function_doc=` for docstring text.
- `RiskLevel` — enum: LOW, MEDIUM, HIGH, CRITICAL
- `Verdict` — enum: APPROVED, DENIED, TIMED_OUT, MODIFIED, ESCALATED
- `ChallengeType` — enum: AUTO_APPROVE, CONFIRM, QUIZ, TEACH_BACK, MULTI_PARTY
- `ChallengeResult` — dataclass: `passed`, `challenge_type`, `details`
- Protocols: `RiskScorer`, `Renderer`, `AuditLoggerProtocol` — structural subtyping

## Code Style and Conventions

- **Python**: ruff for linting (`E, F, I, N, UP, B`), mypy strict mode, line length 120, target Python 3.11
- **TypeScript**: strict mode, dual ESM/CJS output
- **Security patterns**: All user-facing HTML uses `_esc()` / `escapeHtml()` for XSS prevention. CSRF tokens on all web forms. `execFile()` instead of `exec()` for shell commands. File permissions `0o600` for sensitive files (audit, trust data). `asyncio.wait_for()` for approval timeout.
- **EOFError handling**: All terminal input uses try/except `(EOFError, KeyboardInterrupt)` returning empty string.

## File Permissions and Security

- Audit log and trust data files are created with `os.open(..., 0o600)` — owner read/write only.
- Web renderer enforces 64KB POST body limit.
- CSRF tokens use `secrets.token_urlsafe(32)` (Python) / `crypto.randomBytes(32)` (TS).
- `risk_override` hints are blocked by default (`allow_hint_override=False`).

## Common Gotchas

1. **ActionContext.description**: It's a property, not a constructor param. Tests that need a description should set `function_doc=` instead.
2. **System Python vs venv**: The project venv is at `.venv/`. System Python may be 3.9 — always use `.venv/bin/python`.
3. **Node version for docs**: Mintlify requires Node <25. Use `nvm use 22` if needed.
4. **TypeScript non-TTY behavior**: Defaults to DENY (not auto-approve like Python). This is intentional.
5. **OSS_SCOPE.md**: Internal strategy doc, gitignored — don't commit or reference in public-facing content.

## What NOT to Modify

- **OSS boundary**: The `scripts/check_release_boundary.sh` script validates that proprietary code stays out of the OSS release.
- **Hash chain format**: The JSONL audit format is a backwards-compatibility contract. Don't change the hashing algorithm or field order.
- **Zero-dependency core**: The Python core has zero required dependencies. All extras are optional.

## CI

GitHub Actions workflow at `.github/workflows/ci.yaml` runs:
- Python tests (3.11, 3.12) with pytest
- TypeScript typecheck + build + test
- ruff lint
- mypy type check
- Release boundary check
