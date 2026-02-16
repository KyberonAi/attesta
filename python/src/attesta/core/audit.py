"""Hash-chained audit logging system.

Every attesta decision is recorded as an :class:`AuditEntry` and appended
to a JSONL file.  Entries are linked by a SHA-256 hash chain: each entry's
``chain_hash`` is the SHA-256 digest of the previous entry's hash
concatenated with the current entry's canonical JSON representation.  This
makes post-hoc tampering detectable via :meth:`AuditLogger.verify_chain`.

The JSONL format was chosen for simplicity, portability, and ease of
streaming analysis with standard Unix tools.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from attesta.core.types import (
    ActionContext,
    ApprovalResult,
    ChallengeType,
    RiskLevel,
    Verdict,
)

__all__ = ["AuditEntry", "AuditLogger"]

logger = logging.getLogger("attesta.audit")

_GENESIS_HASH = "0" * 64  # SHA-256 zero hash for the first entry in the chain


# ---------------------------------------------------------------------------
# AuditEntry
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """A single, immutable audit record for one attesta decision.

    All fields are plain, JSON-serialisable types so the entry can be
    written to JSONL without custom encoders.
    """

    # Identity
    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    # Hash chain
    chain_hash: str = ""
    previous_hash: str = ""

    # Action details
    action_name: str = ""
    action_description: str = ""

    # Agent
    agent_id: str = ""

    # Risk
    risk_score: float = 0.0
    risk_level: str = ""  # RiskLevel.value

    # Challenge
    challenge_type: str = ""  # ChallengeType.value
    challenge_passed: bool | None = None

    # Approval
    approver_ids: list[str] = field(default_factory=list)
    verdict: str = ""  # Verdict.value
    review_duration_seconds: float = 0.0
    min_review_met: bool = True

    # Timestamps
    intercepted_at: str = ""  # ISO-8601
    decided_at: str = ""  # ISO-8601
    executed_at: str = ""  # ISO-8601

    # Context
    session_id: str = ""
    environment: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict suitable for JSON serialisation."""
        return asdict(self)

    def to_json(self) -> str:
        """Canonical JSON string (sorted keys, no extra whitespace)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Reconstruct an :class:`AuditEntry` from a plain dict."""
        # Only pass fields that exist on the dataclass to tolerate schema drift.
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    @classmethod
    def from_json(cls, line: str) -> AuditEntry:
        """Reconstruct an :class:`AuditEntry` from a JSON string."""
        return cls.from_dict(json.loads(line))

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    def _hashable_dict(self) -> dict[str, Any]:
        """Return the dict used for hash computation (excludes chain_hash)."""
        d = self.to_dict()
        d.pop("chain_hash", None)
        return d

    def _hashable_json(self) -> str:
        """Canonical JSON of all fields except ``chain_hash``."""
        return json.dumps(self._hashable_dict(), sort_keys=True, separators=(",", ":"))

    def compute_hash(self, previous_hash: str) -> str:
        """Compute the SHA-256 chain hash for this entry.

        ``hash = sha256(previous_hash + canonical_json_without_chain_hash)``
        """
        payload = previous_hash + self._hashable_json()
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Builder: ActionContext + ApprovalResult -> AuditEntry
# ---------------------------------------------------------------------------

def build_entry(
    ctx: ActionContext,
    result: ApprovalResult,
    *,
    min_review_seconds: float = 0.0,
) -> AuditEntry:
    """Convenience factory that populates an :class:`AuditEntry` from the
    core types produced during a gate evaluation.
    """
    now_iso = datetime.now().isoformat()

    challenge_type = ""
    challenge_passed: bool | None = None
    if result.challenge_result is not None:
        challenge_type = result.challenge_result.challenge_type.value
        challenge_passed = result.challenge_result.passed

    return AuditEntry(
        action_name=ctx.function_name,
        action_description=ctx.description,
        agent_id=ctx.agent_id or "",
        risk_score=result.risk_assessment.score,
        risk_level=result.risk_assessment.level.value,
        challenge_type=challenge_type,
        challenge_passed=challenge_passed,
        approver_ids=list(result.approvers),
        verdict=result.verdict.value,
        review_duration_seconds=result.review_time_seconds,
        min_review_met=(result.review_time_seconds >= min_review_seconds),
        intercepted_at=ctx.timestamp.isoformat(),
        decided_at=result.timestamp.isoformat(),
        executed_at=now_iso if result.verdict == Verdict.APPROVED else "",
        session_id=ctx.session_id or "",
        environment=ctx.environment,
        metadata=dict(ctx.metadata),
    )


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Hash-chained JSONL audit logger.

    Each call to :meth:`log` appends a new :class:`AuditEntry` to the JSONL
    file with its ``chain_hash`` computed from the previous entry's hash.
    The chain can be verified at any time with :meth:`verify_chain`.

    Parameters
    ----------
    path:
        Filesystem path for the JSONL audit log.  Parent directories are
        created automatically.
    """

    def __init__(self, path: str | Path = ".attesta/audit.jsonl") -> None:
        self.path = Path(path)
        self._last_hash: str = _GENESIS_HASH
        self._entry_count: int = 0

        # Resume from existing log if present.
        if self.path.exists():
            self._resume_chain()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        """Persist an audit entry and return its ``entry_id``.

        This method satisfies the :class:`attesta.core.types.AuditLogger`
        protocol so an ``AuditLogger`` instance can be passed directly to
        :class:`attesta.core.gate.Attesta`.
        """
        entry = build_entry(ctx, result)
        self._append(entry)
        return entry.entry_id

    def log_entry(self, entry: AuditEntry) -> None:
        """Directly log a pre-built :class:`AuditEntry`.

        Useful for programmatic auditing outside the gate pipeline (e.g.
        recording trust incidents or manual overrides).
        """
        self._append(entry)

    def verify_chain(self) -> tuple[bool, int, list[int]]:
        """Verify the integrity of the entire audit chain.

        Returns
        -------
        tuple[bool, int, list[int]]
            ``(intact, total_entries, broken_link_indices)``

            - ``intact`` is ``True`` if every entry's hash is valid.
            - ``total_entries`` is the number of entries checked.
            - ``broken_link_indices`` lists the 0-based indices of entries
              whose hash does not match the recomputed value.
        """
        if not self.path.exists():
            return (True, 0, [])

        broken: list[int] = []
        previous_hash = _GENESIS_HASH
        total = 0

        with self.path.open("r", encoding="utf-8") as fh:
            for idx, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                total += 1

                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError) as exc:
                    logger.warning("Malformed entry at line %d: %s", idx, exc)
                    broken.append(idx)
                    # Cannot derive hash from broken entry -- keep previous_hash unchanged.
                    # Next valid entry's chain verification will also fail, which correctly
                    # reflects that the chain is broken from this point.
                    continue

                expected = entry.compute_hash(previous_hash)
                if entry.chain_hash != expected:
                    broken.append(idx)

                # Advance the chain regardless so we can detect *which* links
                # are broken rather than cascading all subsequent entries.
                previous_hash = entry.chain_hash

        intact = len(broken) == 0
        return (intact, total, broken)

    def query(self, **filters: Any) -> list[AuditEntry]:
        """Return entries matching all supplied filters.

        Supported filter keys
        ---------------------
        - ``risk_level`` (str): exact match on ``risk_level``.
        - ``verdict`` (str): exact match on ``verdict``.
        - ``agent_id`` (str): exact match on ``agent_id``.
        - ``session_id`` (str): exact match on ``session_id``.
        - ``environment`` (str): exact match on ``environment``.
        - ``action_name`` (str): exact match on ``action_name``.
        - ``from_date`` (str | datetime): entries on or after this time.
        - ``to_date`` (str | datetime): entries on or before this time.
        - ``challenge_passed`` (bool): match on ``challenge_passed``.

        Unrecognised keys are silently ignored.
        """
        if not self.path.exists():
            return []

        # Normalise enum values if the caller passes enum instances.
        for key in ("risk_level", "verdict", "challenge_type"):
            val = filters.get(key)
            if val is not None and hasattr(val, "value"):
                filters[key] = val.value

        from_dt = _parse_dt(filters.get("from_date"))
        to_dt = _parse_dt(filters.get("to_date"))

        results: list[AuditEntry] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError):
                    continue

                if not self._matches(entry, filters, from_dt, to_dt):
                    continue
                results.append(entry)
        return results

    def export(
        self,
        format: str = "csv",
        output: Any = None,
        **filters: Any,
    ) -> None:
        """Export audit entries to CSV or JSON.

        Parameters
        ----------
        format:
            ``"csv"`` or ``"json"``.
        output:
            A file-like object to write to.  If ``None``, writes to stdout.
        **filters:
            Passed to :meth:`query` to filter entries before export.
        """
        import sys
        from attesta.exporters import CSVExporter, JSONExporter

        if output is None:
            output = sys.stdout

        entries = self.query(**filters) if filters else self._read_all()

        if format.lower() == "json":
            JSONExporter().export(entries, output)
        else:
            CSVExporter().export(entries, output)

    def _read_all(self) -> list[AuditEntry]:
        """Read all entries from the log file."""
        if not self.path.exists():
            return []
        entries: list[AuditEntry] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(AuditEntry.from_json(line))
                except (json.JSONDecodeError, TypeError):
                    continue
        return entries

    def find_rubber_stamps(
        self,
        max_review_seconds: float = 5.0,
        min_risk: str = "high",
    ) -> list[AuditEntry]:
        """Find suspiciously fast approvals on high-risk actions.

        A "rubber stamp" is an approved entry where:

        - The ``risk_level`` is at or above *min_risk* (ordered
          low < medium < high < critical).
        - The ``review_duration_seconds`` is at most *max_review_seconds*.
        - The ``verdict`` is ``"approved"``.

        Parameters
        ----------
        max_review_seconds:
            Upper bound on review time to flag (default 5 s).
        min_risk:
            Minimum risk level to consider (default ``"high"``).

        Returns
        -------
        list[AuditEntry]
            Entries that look like rubber stamps, in file order.
        """
        risk_order = _risk_level_order()
        min_risk_idx = risk_order.get(min_risk.lower(), 2)

        if not self.path.exists():
            return []

        stamps: list[AuditEntry] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError):
                    continue

                if entry.verdict != Verdict.APPROVED.value:
                    continue
                entry_risk_idx = risk_order.get(entry.risk_level.lower(), -1)
                if entry_risk_idx < min_risk_idx:
                    continue
                if entry.review_duration_seconds > max_review_seconds:
                    continue
                stamps.append(entry)
        return stamps

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _append(self, entry: AuditEntry) -> None:
        """Compute chain hash, set it on the entry, and write to disk."""
        entry.previous_hash = self._last_hash
        entry.chain_hash = entry.compute_hash(self._last_hash)
        self._last_hash = entry.chain_hash
        self._entry_count += 1

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Use restrictive permissions (owner read/write only) for audit files
        import os
        if not self.path.exists():
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(entry.to_json() + "\n")

        logger.debug(
            "Audit entry %s written (chain_hash=%s...)",
            entry.entry_id,
            entry.chain_hash[:12],
        )

    def _resume_chain(self) -> None:
        """Read the existing log to recover ``_last_hash`` and entry count."""
        count = 0
        last_hash = _GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    data = json.loads(line)
                    last_hash = data.get("chain_hash", last_hash)
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed line during resume")
        self._last_hash = last_hash
        self._entry_count = count
        logger.debug(
            "Resumed audit chain with %d entries (last_hash=%s...)",
            count,
            last_hash[:12],
        )

    @staticmethod
    def _matches(
        entry: AuditEntry,
        filters: dict[str, Any],
        from_dt: datetime | None,
        to_dt: datetime | None,
    ) -> bool:
        """Return ``True`` if *entry* matches all *filters*."""
        # Simple equality filters.
        _SIMPLE_KEYS = (
            "risk_level",
            "verdict",
            "agent_id",
            "session_id",
            "environment",
            "action_name",
            "challenge_type",
        )
        for key in _SIMPLE_KEYS:
            if key in filters and filters[key] is not None:
                if getattr(entry, key, None) != filters[key]:
                    return False

        if "challenge_passed" in filters and filters["challenge_passed"] is not None:
            if entry.challenge_passed != filters["challenge_passed"]:
                return False

        # Date range filters (based on intercepted_at).
        if from_dt or to_dt:
            entry_dt = _parse_dt(entry.intercepted_at)
            if entry_dt is None:
                # Cannot compare -- exclude from date-filtered results.
                return False
            if from_dt and entry_dt < from_dt:
                return False
            if to_dt and entry_dt > to_dt:
                return False

        return True


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _parse_dt(value: Any) -> datetime | None:
    """Coerce a string or datetime to a ``datetime``, or ``None``."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _risk_level_order() -> dict[str, int]:
    """Return a mapping from risk-level name to its ordinal rank."""
    return {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }
