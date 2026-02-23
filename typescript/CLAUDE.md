# Attesta — TypeScript SDK

## Stack

- TypeScript 5, strict mode
- Build: tsup dual ESM + CJS output
- Test: Node.js native test runner
- Node.js 18+
- Zero runtime dependencies (Node.js built-ins only)

## Structure

```
typescript/
├── src/
│   ├── index.ts             # Re-exports all public types and classes
│   ├── types.ts             # Enums, interfaces, protocols, factory functions
│   ├── gate.ts              # Attesta class + gate() decorator
│   ├── risk.ts              # Risk scorers (Default, Composite, Max, Fixed)
│   ├── trust.ts             # Bayesian adaptive trust engine
│   ├── audit.ts             # SHA-256 hash-chained JSONL audit logger
│   ├── challenges/          # confirm, quiz, teach-back, validators
│   ├── renderers/           # terminal (chalk), web (async HTTP)
│   ├── integrations/        # langchain, vercel-ai
│   ├── environment.ts       # Environment detection
│   ├── events.ts            # Event bus
│   ├── exporters.ts         # CSV/JSON export
│   └── webhooks.ts          # Webhook dispatch
├── tests/
├── package.json
└── tsconfig.json
```

## Commands

```bash
cd typescript
npm install
npm run typecheck   # tsc --noEmit
npm run build       # compile ESM + CJS
npm test            # node --test
```

## Conventions

- Mirrors Python SDK — same public API (snake_case → camelCase)
- Same algorithms, same edge case handling, same error types
- Must pass shared test vectors from `fixtures/test-vectors.json`
- No `any` types — use `unknown` + type guards
- JSDoc on public APIs
- Non-TTY defaults to DENY (Python defaults to auto-approve)
- HTML escaping via `escapeHtml()` in web renderer
- `execFile()` not `exec()` for shell operations
- SHA-256 via Node.js `crypto` with Web Crypto API fallback

## SDK Parity Rules

1. Both SDKs produce identical output for the same input data
2. Same canonical JSON algorithm
3. Same genesis hash ("0" × 64)
4. Same risk scoring factors and weights
5. Same error types: AttestaDenied, ValidationError
6. Same interface contracts (Protocol in Python = interface in TS)

## What NOT To Do

- Do not diverge from Python SDK behavior
- Do not add runtime dependencies
- Do not modify package.json without asking
- Do not change the hash chain format
