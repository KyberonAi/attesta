# Maintainer Operations

This runbook defines how maintainers triage inbound work and keep OSS operations predictable.

## Ownership Source

`CODEOWNERS` is the canonical ownership map for review routing.

## Triage Cadence

- Issue and PR triage: Monday/Wednesday/Friday
- Security advisory triage: daily business-day check
- Release readiness review: weekly during active release windows

## Labels

Use these labels consistently during triage:

- `needs-triage`
- `bug`
- `enhancement`
- `documentation`
- `security`
- `maintainer-escalation`
- `good first issue`

## Triage Flow

1. Confirm reproducibility or request a minimal reproduction.
2. Classify severity and impact scope.
3. Assign owner based on `CODEOWNERS`.
4. Mark milestone (`next-patch`, `next-minor`, or `backlog`).
5. Post next-step ETA.

## Security and Dependency Exceptions

- Track temporary dependency exceptions in `security/dependency-exceptions.md`.
- Each exception must include owner and expiry date.
- Expired exceptions must be resolved or re-approved in the next release review.

## Release Captain Checklist

Before tagging a release, release captain confirms:

- `.github/BRANCH_PROTECTION_CHECKLIST.md` is satisfied for `main`
- `RELEASE_CHECKLIST.md` completed
- `SECURITY.md` and `SUPPORT.md` still accurate
- exception expiries in `security/dependency-exceptions.md` reviewed
- docs and quickstart paths are up to date
- pre-release tag was cut and recorded via `scripts/cut_release_candidate.sh`
