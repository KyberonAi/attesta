# Attesta

**Attesta** is an open-core Human-in-the-Loop (HITL) approval framework for AI agents. It scores action risk and selects verification challenges proportional to that risk — from auto-approving safe reads to requiring multi-party sign-off for irreversible operations.

## Stack

- Python 3.11+ / TypeScript 5 / Node.js 18+
- Zero runtime dependencies in both SDKs (stdlib/built-ins only)
- Build: hatchling (Python), tsup ESM+CJS (TypeScript)
- Audit: TrailProof for tamper-evident hash-chained event logging

## Project Structure

```
attesta/
├── .claude/           commands, agents, templates, skills, specs, plans, decisions
├── python/            Python SDK (built first)
│   ├── src/attesta/
│   └── tests/
├── typescript/        TypeScript SDK (mirrors Python)
│   ├── src/
│   └── tests/
├── packages/          No-code integrations (n8n, Flowise, Langflow, Dify)
├── fixtures/          Shared cross-SDK test vectors (JSON)
├── docs/              Mintlify documentation site
├── .github/workflows/ CI/CD
└── CLAUDE.md
```

## Core Concepts

- **Risk Scoring** — 5-factor weighted scorer assigns 0-1 risk to every action
- **Challenge System** — confirm, quiz, teach-back, multi-party challenges proportional to risk
- **Trust Engine** — Bayesian adaptive trust per-agent/per-domain, decays over time
- **Audit Trail** — TrailProof-backed tamper-evident hash-chained event log
- **Two Attesta Classes** — `attesta/__init__.py:Attesta` (public API) vs `core/gate.py:CoreAttesta` (internal orchestrator)

## Commands

- Python: see `python/CLAUDE.md` for test/lint/typecheck commands
- TypeScript: see `typescript/CLAUDE.md` for npm scripts
- No-code packages: `PYTHONPATH=python/src pytest packages/{pkg}/tests -q`
- Docs: `cd docs && npx mintlify dev` (requires Node LTS 22, NOT 25+)

## Architecture

### Request Flow

```
@gate decorator or Attesta.evaluate(ctx)
  → CoreAttesta.evaluate(ActionContext)
    → RiskScorer.score(ctx) → float [0,1]
    → TrustEngine.effective_risk() (if configured) → adjusted score
    → RiskLevel.from_score() → LOW/MEDIUM/HIGH/CRITICAL
    → challenge_map[risk_level] → ChallengeType
    → asyncio.wait_for(Renderer.render_challenge(...), timeout)
    → AuditLogger.log(entry) → TrailProof tp.emit()
    → ApprovalResult
```

### Key Modules

- **`core/types.py`** — All enums, dataclasses, and protocols. Zero internal deps.
- **`core/risk.py`** — DefaultRiskScorer (5-factor), CompositeRiskScorer, MaxRiskScorer, FixedRiskScorer.
- **`core/trust.py`** — Bayesian adaptive trust. Exponential decay, per-agent/per-domain.
- **`core/audit.py`** — SHA-256 hash-chained JSONL (legacy). TrailProof backend available.
- **`challenges/`** — confirm, quiz, teach_back, multi_party.
- **`renderers/`** — terminal (rich), web (async HTTP). Non-TTY: auto-approve (Python), deny (TS).
- **`integrations/`** — LangChain, OpenAI Agents, CrewAI, Anthropic, MCP.
- **`domains/`** — DomainProfile, DomainRiskScorer, presets (devops, data_pipeline).
- **`config/loader.py`** — YAML → Policy dataclass.

## SDK Parity Rules

1. Both SDKs produce identical output for the same input data
2. Same algorithms in both SDKs
3. Pass the same test vectors from `fixtures/test-vectors.json`
4. Same public API (snake_case in Python, camelCase in TypeScript)
5. Same error types: AttestaDenied, ValidationError
6. Same interface contracts in both SDKs

## Conventions

### Error Messages
```
Attesta: {what went wrong} — {context}
```

### Commit Messages
- Use conventional commits (feat:, fix:, chore:, docs:, test:)
- Present tense, explain "why" not just "what"
- Do NOT append "Co-Authored-By" trailers

### Build Order
Python first, TypeScript mirrors after. Each step: Python → TypeScript → shared test vectors → commit.

### Security
- HTML escaping via `_esc()`/`escapeHtml()`
- CSRF tokens on all web forms
- `execFile()` not `exec()` for shell operations
- File permissions `0o600` for audit/trust files
- `asyncio.wait_for()` for approval timeout
- Terminal input wrapped in `try/except (EOFError, KeyboardInterrupt)`
- All extensibility uses `typing.Protocol` (structural subtyping)

## Critical Gotchas

1. **`ActionContext.description` is a property**, not a constructor param. Derived from `function_name` + `args`. Use `function_doc=` for docstring text.
2. **System Python vs venv**: Project venv is at `.venv/`. Always use `.venv/bin/python`.
3. **Zero-dependency core**: Don't add required deps to either SDK.
4. **Hash chain format**: JSONL audit format is a backwards-compatibility contract.
5. **OSS_SCOPE.md**: Internal strategy doc, gitignored. Don't reference publicly.
6. **`risk_override` hints**: Blocked by default (`allow_hint_override=False`).

## Workflow Rules

1. No code without an approved spec in `.claude/specs/`
2. Spec → Plan → Build → Test → Review → Commit
3. One task = one commit
4. Run tests before every commit
5. Update plan files to reflect state after each session

## What NOT To Do

- Do not write code without an approved spec
- Do not modify pyproject.toml or package.json without asking
- Do not add dependencies without asking (both SDKs must stay zero-dep at runtime)
- Do not continue to the next task without stopping for review
- Do not commit or reference OSS_SCOPE.md in public content
