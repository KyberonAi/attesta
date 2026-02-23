# ADR-001: Adopt Kyberon Workflow

## Status
Accepted

## Context
Attesta was developed without a structured development workflow. As the project grows and multiple contributors join, we need a consistent process for spec → plan → build → review → commit cycles.

The Kyberon workflow template provides:
- Structured .claude/ directory with commands, agents, templates, skills
- Multi-agent patterns for parallel development (parallel-mirror, review-agent, parallel-build)
- Convention-based settings and hooks for code quality

## Decision
Adopt the Kyberon workflow template as our standard development process. This includes:
1. All features start with a spec (.claude/specs/)
2. Specs are planned (.claude/plans/)
3. Builds follow plans using /build command
4. Independent review via review-agent
5. Conventional commits via /commit command
6. Architecture decisions documented as ADRs (.claude/decisions/)

## Consequences
### Positive
- Consistent, repeatable development process
- Better traceability from requirement → implementation
- Multi-agent parallelism reduces build time
- Independent review catches spec drift early

### Negative
- Small overhead for trivial changes (still need spec)
- Learning curve for new contributors unfamiliar with the workflow
- Additional files in .claude/ directory
