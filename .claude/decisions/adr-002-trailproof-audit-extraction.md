# ADR-002: TrailProof Audit Extraction

## Status
Accepted

## Context
Attesta's core audit system uses a hand-rolled SHA-256 hash-chained JSONL logger. While functional, this approach:
- Duplicates work already done in TrailProof (a standalone tamper-evident audit library)
- Lacks HMAC signing for provenance
- Has no multi-tenancy support
- Doesn't support trace/session correlation natively

TrailProof (https://trailproof.kyberon.dev) is a sibling package in the Kyberon AI ecosystem that provides these features with zero dependencies.

## Decision
Introduce a pluggable `AuditBackend` protocol and add `TrailProofBackend` as an optional backend alongside the existing `LegacyBackend`.

Key design choices:
1. **Protocol-based**: `AuditBackend` is a `typing.Protocol` (Python) / `interface` (TypeScript), not an ABC
2. **Optional dependency**: TrailProof is imported lazily inside `TrailProofBackend.__init__()` — the core works without it
3. **Config-driven**: Backend selected via `audit.backend` in attesta.yaml ("legacy" or "trailproof")
4. **Field mapping**: agent_id→actor_id, event_type="attesta.approval.{verdict}", all other fields→payload
5. **No migration**: Legacy and TrailProof audit trails are independent files

## Consequences
### Positive
- Eliminates duplicated audit chain logic
- Gains HMAC signing, multi-tenancy, trace correlation for free
- Pluggable architecture allows future backends (database, cloud API)
- Legacy backend unchanged — zero breaking changes

### Negative
- Two audit formats to document and support
- TrailProof is a runtime dependency (optional) that needs version management
- No automatic migration path from legacy to TrailProof
