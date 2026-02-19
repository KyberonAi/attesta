# Dependency Security Exceptions

This file tracks temporary exceptions for dependency vulnerabilities that cannot
be immediately remediated without breaking changes.

Status keys:

- `OPEN`: accepted temporary risk, still unresolved
- `CLOSED`: remediated

## Open Exceptions

| ID | Package Scope | Advisory Summary | Severity | Owner | Rationale | Expiry |
|----|---------------|------------------|----------|-------|-----------|--------|
| DEP-001 | `packages/flowise-attesta` | Multiple transitive vulnerabilities inherited from upstream `flowise-components` chain | mixed (high/critical) | `@kyberon/security` | Upstream major-version upgrade required; tracked while integration remains optional/non-core | 2026-04-30 |
| DEP-002 | `packages/n8n-nodes-attesta` | Transitive vulnerabilities from optional ecosystem packages (`n8n-workflow` tree) | mixed (high/critical) | `@kyberon/security` | Requires upstream dependency refresh from n8n ecosystem; mitigation is scoped usage and regular upgrade watch | 2026-04-30 |

## Closure Rules

An exception can be closed only when:

1. the vulnerable dependency is upgraded or removed, and
2. CI audit output confirms no unresolved finding for that exception scope.
