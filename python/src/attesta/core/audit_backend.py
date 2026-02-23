"""Pluggable audit backend abstraction.

Defines the :class:`AuditBackend` protocol and provides two implementations:

1. :class:`LegacyBackend` -- wraps the existing :class:`AuditLogger` (default).
2. :class:`TrailProofBackend` -- delegates to TrailProof for tamper-evident event logging.

The backend is selected via ``audit.backend`` in ``attesta.yaml``::

    audit:
      backend: trailproof   # or "legacy" (default)
      path: events.jsonl
      tenant_id: my-org
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from attesta.core.types import ActionContext, ApprovalResult, Verdict

__all__ = ["AuditBackend", "LegacyBackend", "TrailProofBackend", "create_backend"]

logger = logging.getLogger("attesta.audit")


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class AuditBackend(Protocol):
    """Pluggable audit storage backend.

    Any object with ``log``, ``verify``, and ``query`` methods that match
    these signatures can serve as an audit backend.
    """

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        """Persist an audit record and return a unique entry ID."""
        ...

    def verify(self) -> tuple[bool, int, list[int]]:
        """Verify chain integrity. Returns ``(intact, total, broken_indices)``."""
        ...

    def query(self, **filters: Any) -> list[Any]:
        """Return entries matching the supplied filters."""
        ...


# ---------------------------------------------------------------------------
# Legacy backend (wraps existing AuditLogger)
# ---------------------------------------------------------------------------


class LegacyBackend:
    """Wraps the existing :class:`~attesta.core.audit.AuditLogger`.

    This is the default backend when no ``audit.backend`` is configured.
    Preserves full backward compatibility with the existing JSONL audit log.
    """

    def __init__(self, path: str = ".attesta/audit.jsonl") -> None:
        from attesta.core.audit import AuditLogger

        self._logger = AuditLogger(path=path)

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        return await self._logger.log(ctx, result)

    def verify(self) -> tuple[bool, int, list[int]]:
        return self._logger.verify_chain()

    def query(self, **filters: Any) -> list[Any]:
        return self._logger.query(**filters)

    def find_rubber_stamps(self, **kwargs: Any) -> list[Any]:
        return self._logger.find_rubber_stamps(**kwargs)


# ---------------------------------------------------------------------------
# TrailProof backend
# ---------------------------------------------------------------------------


class TrailProofBackend:
    """Delegates audit logging to TrailProof.

    Requires: ``pip install trailproof``

    Maps Attesta audit fields to TrailProof's 10-field event envelope:
    - ``agent_id`` → ``actor_id``
    - ``session_id`` → ``session_id``
    - ``tenant_id`` from config → ``tenant_id``
    - Event type: ``attesta.approval.{verdict}``
    - All other Attesta-specific fields → ``payload``
    """

    def __init__(
        self,
        *,
        path: str = ".attesta/audit.jsonl",
        tenant_id: str = "default",
        hmac_key: str | None = None,
    ) -> None:
        try:
            from trailproof import Trailproof
        except ImportError:
            raise ImportError(
                "TrailProof is required for the trailproof audit backend. Install with: pip install attesta[trailproof]"
            ) from None

        kwargs: dict[str, Any] = {"store": "jsonl", "path": path}
        if hmac_key is not None:
            kwargs["hmac_key"] = hmac_key

        self._tp = Trailproof(**kwargs)
        self._tenant_id = tenant_id

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        """Emit a TrailProof event from Attesta audit data."""
        from attesta.core.audit import build_entry

        entry = build_entry(ctx, result)

        verdict_str = result.verdict.value if isinstance(result.verdict, Verdict) else str(result.verdict)
        event_type = f"attesta.approval.{verdict_str}"

        # All Attesta-specific fields go into the opaque payload
        payload = {
            "action_name": entry.action_name,
            "action_description": entry.action_description,
            "risk_score": entry.risk_score,
            "risk_level": entry.risk_level,
            "challenge_type": entry.challenge_type,
            "challenge_passed": entry.challenge_passed,
            "approver_ids": entry.approver_ids,
            "verdict": entry.verdict,
            "review_duration_seconds": entry.review_duration_seconds,
            "min_review_met": entry.min_review_met,
            "intercepted_at": entry.intercepted_at,
            "decided_at": entry.decided_at,
            "executed_at": entry.executed_at,
            "environment": entry.environment,
            "metadata": entry.metadata,
        }

        event = self._tp.emit(
            event_type=event_type,
            actor_id=ctx.agent_id or "unknown",
            tenant_id=self._tenant_id,
            payload=payload,
            session_id=ctx.session_id or None,
        )

        return event.event_id

    def verify(self) -> tuple[bool, int, list[int]]:
        """Verify the TrailProof chain integrity."""
        result = self._tp.verify()
        return (result.intact, result.total, list(result.broken))

    def query(self, **filters: Any) -> list[Any]:
        """Query TrailProof events with Attesta-compatible filters."""
        tp_filters: dict[str, Any] = {}

        # Map Attesta filter keys to TrailProof query params
        if "agent_id" in filters:
            tp_filters["actor_id"] = filters["agent_id"]

        if "limit" in filters:
            tp_filters["limit"] = filters["limit"]

        result = self._tp.query(**tp_filters)
        return list(result.events)

    def flush(self) -> None:
        """Ensure all data is flushed to disk."""
        self._tp.flush()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_backend(
    backend: str = "legacy",
    *,
    path: str = ".attesta/audit.jsonl",
    tenant_id: str = "default",
    hmac_key: str | None = None,
) -> LegacyBackend | TrailProofBackend:
    """Create an audit backend by name.

    Parameters
    ----------
    backend:
        ``"legacy"`` (default) or ``"trailproof"``.
    path:
        File path for the JSONL audit log.
    tenant_id:
        Tenant identifier for TrailProof backend.
    hmac_key:
        Optional HMAC signing key for TrailProof backend.
    """
    backend = backend.strip().lower()

    if backend == "trailproof":
        return TrailProofBackend(path=path, tenant_id=tenant_id, hmac_key=hmac_key)
    elif backend in ("legacy", "default", ""):
        return LegacyBackend(path=path)
    else:
        raise ValueError(f"Unknown audit backend: {backend!r}. Use 'legacy' or 'trailproof'.")
