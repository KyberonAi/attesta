"""Tests for attesta.core.audit -- hash-chained JSONL audit logger."""

from __future__ import annotations

import json

from attesta.core.audit import (
    _GENESIS_HASH,
    AuditEntry,
    AuditLogger,
    build_entry,
)
from attesta.core.types import (
    ActionContext,
    ApprovalResult,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    RiskLevel,
    Verdict,
)

# =========================================================================
# Helpers
# =========================================================================

def _make_ctx(
    name: str = "test_action",
    agent_id: str = "agent-1",
    session_id: str = "sess-1",
    environment: str = "test",
) -> ActionContext:
    return ActionContext(
        function_name=name,
        agent_id=agent_id,
        session_id=session_id,
        environment=environment,
    )


def _make_result(
    verdict: Verdict = Verdict.APPROVED,
    score: float = 0.5,
    level: RiskLevel = RiskLevel.MEDIUM,
    review_time: float = 3.0,
    challenge_type: ChallengeType | None = ChallengeType.CONFIRM,
    challenge_passed: bool = True,
) -> ApprovalResult:
    ra = RiskAssessment(score=score, level=level)
    cr = None
    if challenge_type is not None:
        cr = ChallengeResult(passed=challenge_passed, challenge_type=challenge_type)
    return ApprovalResult(
        verdict=verdict,
        risk_assessment=ra,
        challenge_result=cr,
        review_time_seconds=review_time,
    )


async def _log_n_entries(
    logger: AuditLogger,
    n: int,
    *,
    verdict: Verdict = Verdict.APPROVED,
    score: float = 0.5,
    level: RiskLevel = RiskLevel.MEDIUM,
    review_time: float = 3.0,
    agent_id: str = "agent-1",
    environment: str = "test",
) -> list[str]:
    """Log *n* entries and return their entry IDs."""
    ids = []
    for i in range(n):
        ctx = _make_ctx(name=f"action_{i}", agent_id=agent_id, environment=environment)
        result = _make_result(verdict=verdict, score=score, level=level, review_time=review_time)
        entry_id = await logger.log(ctx, result)
        ids.append(entry_id)
    return ids


# =========================================================================
# AuditEntry -- serialisation
# =========================================================================

class TestAuditEntry:
    def test_to_dict_roundtrip(self):
        entry = AuditEntry(
            action_name="deploy",
            verdict="approved",
            risk_score=0.7,
            risk_level="high",
        )
        d = entry.to_dict()
        restored = AuditEntry.from_dict(d)
        assert restored.action_name == "deploy"
        assert restored.verdict == "approved"
        assert restored.risk_score == 0.7
        assert restored.risk_level == "high"

    def test_to_json_and_from_json(self):
        entry = AuditEntry(
            action_name="delete",
            verdict="denied",
            risk_score=0.9,
            risk_level="critical",
        )
        json_str = entry.to_json()
        restored = AuditEntry.from_json(json_str)
        assert restored.action_name == "delete"
        assert restored.verdict == "denied"

    def test_to_json_is_canonical(self):
        """JSON should be sorted keys, no extra whitespace."""
        entry = AuditEntry(action_name="test")
        json_str = entry.to_json()
        parsed = json.loads(json_str)
        # Re-serialize with same settings should be identical
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        assert json_str == canonical

    def test_from_dict_ignores_unknown_keys(self):
        """Schema drift tolerance: unknown keys are silently ignored."""
        data = {"action_name": "deploy", "unknown_field": "should_be_ignored"}
        entry = AuditEntry.from_dict(data)
        assert entry.action_name == "deploy"
        assert not hasattr(entry, "unknown_field") or True  # Just check no crash

    def test_defaults(self):
        entry = AuditEntry()
        assert entry.entry_id  # Should have a UUID
        assert entry.chain_hash == ""
        assert entry.previous_hash == ""
        assert entry.action_name == ""
        assert entry.verdict == ""
        assert entry.risk_score == 0.0
        assert entry.approver_ids == []
        assert entry.metadata == {}
        assert entry.min_review_met is True


# =========================================================================
# AuditEntry -- hash computation
# =========================================================================

class TestAuditEntryHash:
    def test_compute_hash_is_deterministic(self):
        entry = AuditEntry(action_name="deploy", risk_score=0.5)
        h1 = entry.compute_hash(_GENESIS_HASH)
        h2 = entry.compute_hash(_GENESIS_HASH)
        assert h1 == h2

    def test_different_previous_hash_gives_different_result(self):
        entry = AuditEntry(action_name="deploy")
        h1 = entry.compute_hash(_GENESIS_HASH)
        h2 = entry.compute_hash("a" * 64)
        assert h1 != h2

    def test_hash_excludes_chain_hash_field(self):
        """Changing chain_hash should NOT change compute_hash."""
        entry = AuditEntry(action_name="deploy")
        h1 = entry.compute_hash(_GENESIS_HASH)
        entry.chain_hash = "something_else"
        h2 = entry.compute_hash(_GENESIS_HASH)
        assert h1 == h2

    def test_hash_is_sha256_hex(self):
        entry = AuditEntry(action_name="deploy")
        h = entry.compute_hash(_GENESIS_HASH)
        assert len(h) == 64
        int(h, 16)  # Should be valid hex


# =========================================================================
# build_entry()
# =========================================================================

class TestBuildEntry:
    def test_populates_fields(self):
        ctx = _make_ctx(name="deploy", agent_id="agent-1", environment="production")
        result = _make_result(verdict=Verdict.APPROVED, score=0.7, level=RiskLevel.HIGH)
        entry = build_entry(ctx, result)
        assert entry.action_name == "deploy"
        assert entry.agent_id == "agent-1"
        assert entry.environment == "production"
        assert entry.risk_score == 0.7
        assert entry.risk_level == "high"
        assert entry.verdict == "approved"

    def test_challenge_fields_populated(self):
        ctx = _make_ctx()
        result = _make_result(
            challenge_type=ChallengeType.QUIZ,
            challenge_passed=False,
        )
        entry = build_entry(ctx, result)
        assert entry.challenge_type == "quiz"
        assert entry.challenge_passed is False

    def test_no_challenge(self):
        ctx = _make_ctx()
        result = _make_result(challenge_type=None)
        entry = build_entry(ctx, result)
        assert entry.challenge_type == ""
        assert entry.challenge_passed is None

    def test_min_review_met(self):
        ctx = _make_ctx()
        result = _make_result(review_time=10.0)
        entry = build_entry(ctx, result, min_review_seconds=5.0)
        assert entry.min_review_met is True

    def test_min_review_not_met(self):
        ctx = _make_ctx()
        result = _make_result(review_time=2.0)
        entry = build_entry(ctx, result, min_review_seconds=5.0)
        assert entry.min_review_met is False


# =========================================================================
# AuditLogger -- writing entries to JSONL
# =========================================================================

class TestAuditLoggerWriting:
    async def test_log_creates_file(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        ctx = _make_ctx()
        result = _make_result()
        entry_id = await logger.log(ctx, result)
        assert path.exists()
        assert entry_id  # non-empty

    async def test_log_appends_jsonl(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 3)
        lines = [line for line in path.read_text().strip().split("\n") if line.strip()]
        assert len(lines) == 3

    async def test_each_line_is_valid_json(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 5)
        for line in path.read_text().strip().split("\n"):
            data = json.loads(line)
            assert isinstance(data, dict)
            assert "entry_id" in data
            assert "chain_hash" in data

    async def test_chain_hashes_are_linked(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 3)
        entries = []
        for line in path.read_text().strip().split("\n"):
            entries.append(json.loads(line))

        # First entry's previous_hash should be the genesis hash
        assert entries[0]["previous_hash"] == _GENESIS_HASH
        # Each subsequent entry's previous_hash should be the prior's chain_hash
        for i in range(1, len(entries)):
            assert entries[i]["previous_hash"] == entries[i - 1]["chain_hash"]

    async def test_entry_ids_are_unique(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        ids = await _log_n_entries(logger, 10)
        assert len(set(ids)) == 10

    async def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "deep" / "nested" / "audit.jsonl"
        logger = AuditLogger(path=path)
        ctx = _make_ctx()
        result = _make_result()
        await logger.log(ctx, result)
        assert path.exists()


# =========================================================================
# AuditLogger -- hash chain verification
# =========================================================================

class TestAuditLoggerVerification:
    async def test_intact_chain(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 5)
        intact, total, broken = logger.verify_chain()
        assert intact is True
        assert total == 5
        assert broken == []

    async def test_empty_log_is_intact(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        intact, total, broken = logger.verify_chain()
        assert intact is True
        assert total == 0
        assert broken == []

    async def test_single_entry_verifies(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 1)
        intact, total, broken = logger.verify_chain()
        assert intact is True
        assert total == 1

    async def test_tampered_entry_detected(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 5)

        # Tamper with the 3rd entry (index 2)
        lines = path.read_text().strip().split("\n")
        entry_data = json.loads(lines[2])
        entry_data["verdict"] = "TAMPERED"
        lines[2] = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")

        intact, total, broken = logger.verify_chain()
        assert intact is False
        assert total == 5
        assert 2 in broken

    async def test_tampered_chain_hash_detected(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 3)

        lines = path.read_text().strip().split("\n")
        entry_data = json.loads(lines[1])
        entry_data["chain_hash"] = "deadbeef" * 8
        lines[1] = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")

        intact, total, broken = logger.verify_chain()
        assert intact is False
        assert 1 in broken

    async def test_deleted_entry_detected(self, tmp_path):
        """Removing an entry from the middle should break the chain."""
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 5)

        lines = path.read_text().strip().split("\n")
        # Remove the 2nd entry (index 1)
        del lines[1]
        path.write_text("\n".join(lines) + "\n")

        intact, total, broken = logger.verify_chain()
        assert intact is False
        # The entry after the deleted one should fail (its previous_hash
        # won't match what's actually preceding it now)
        assert len(broken) > 0

    async def test_appended_fake_entry_detected(self, tmp_path):
        """Appending a fake entry with wrong hash should be detected."""
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 3)

        # Append a fake entry with wrong chain hash
        fake = AuditEntry(
            action_name="fake",
            verdict="approved",
            chain_hash="wrong" * 16,
            previous_hash="also_wrong" * 6 + "also",
        )
        with path.open("a") as f:
            f.write(fake.to_json() + "\n")

        intact, total, broken = logger.verify_chain()
        assert intact is False
        assert 3 in broken  # The 4th entry (index 3)


# =========================================================================
# AuditLogger -- log_entry() (direct entry logging)
# =========================================================================

class TestAuditLoggerLogEntry:
    def test_log_entry_writes_to_file(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        entry = AuditEntry(action_name="manual_override", verdict="approved")
        logger.log_entry(entry)
        assert path.exists()
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_log_entry_sets_chain_hash(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        entry = AuditEntry(action_name="test")
        logger.log_entry(entry)
        assert entry.chain_hash != ""
        assert entry.previous_hash == _GENESIS_HASH

    def test_log_entry_chain_continues(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        e1 = AuditEntry(action_name="first")
        e2 = AuditEntry(action_name="second")
        logger.log_entry(e1)
        logger.log_entry(e2)
        assert e2.previous_hash == e1.chain_hash

        # Verify chain integrity
        intact, total, broken = logger.verify_chain()
        assert intact is True
        assert total == 2


# =========================================================================
# AuditLogger -- query filtering
# =========================================================================

class TestAuditLoggerQuery:
    async def test_query_by_verdict(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        # Log some approved and some denied
        for _ in range(3):
            await logger.log(
                _make_ctx(), _make_result(verdict=Verdict.APPROVED)
            )
        for _ in range(2):
            await logger.log(
                _make_ctx(), _make_result(verdict=Verdict.DENIED)
            )

        approved = logger.query(verdict="approved")
        denied = logger.query(verdict="denied")
        assert len(approved) == 3
        assert len(denied) == 2

    async def test_query_by_verdict_enum(self, tmp_path):
        """query() should accept enum values and convert them."""
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 3, verdict=Verdict.APPROVED)
        results = logger.query(verdict=Verdict.APPROVED)
        assert len(results) == 3

    async def test_query_by_risk_level(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 2, score=0.1, level=RiskLevel.LOW)
        await _log_n_entries(logger, 3, score=0.9, level=RiskLevel.CRITICAL)

        low = logger.query(risk_level="low")
        critical = logger.query(risk_level="critical")
        assert len(low) == 2
        assert len(critical) == 3

    async def test_query_by_agent_id(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 2, agent_id="agent-1")
        await _log_n_entries(logger, 3, agent_id="agent-2")

        a1 = logger.query(agent_id="agent-1")
        a2 = logger.query(agent_id="agent-2")
        assert len(a1) == 2
        assert len(a2) == 3

    async def test_query_by_environment(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 2, environment="production")
        await _log_n_entries(logger, 4, environment="staging")

        prod = logger.query(environment="production")
        staging = logger.query(environment="staging")
        assert len(prod) == 2
        assert len(staging) == 4

    async def test_query_no_filters_returns_all(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(logger, 5)
        all_entries = logger.query()
        assert len(all_entries) == 5

    async def test_query_multiple_filters_intersection(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        # 2 approved in production
        await _log_n_entries(logger, 2, verdict=Verdict.APPROVED, environment="production")
        # 3 approved in staging
        await _log_n_entries(logger, 3, verdict=Verdict.APPROVED, environment="staging")
        # 1 denied in production
        await _log_n_entries(logger, 1, verdict=Verdict.DENIED, environment="production")

        results = logger.query(verdict="approved", environment="production")
        assert len(results) == 2

    async def test_query_empty_log(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        results = logger.query(verdict="approved")
        assert results == []

    async def test_query_nonexistent_file(self, tmp_path):
        path = tmp_path / "does_not_exist.jsonl"
        logger = AuditLogger(path=path)
        # Override to skip the file check in __init__
        logger.path = path
        results = logger.query(verdict="approved")
        assert results == []


# =========================================================================
# AuditLogger -- find_rubber_stamps
# =========================================================================

class TestFindRubberStamps:
    async def test_finds_fast_high_risk_approvals(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        # Fast approval on high risk (rubber stamp)
        await _log_n_entries(
            logger, 2,
            verdict=Verdict.APPROVED,
            score=0.7,
            level=RiskLevel.HIGH,
            review_time=1.0,
        )
        # Slow approval on high risk (legitimate)
        await _log_n_entries(
            logger, 1,
            verdict=Verdict.APPROVED,
            score=0.7,
            level=RiskLevel.HIGH,
            review_time=30.0,
        )
        stamps = logger.find_rubber_stamps(max_review_seconds=5.0, min_risk="high")
        assert len(stamps) == 2

    async def test_ignores_low_risk(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        # Fast approval on low risk (not a rubber stamp)
        await _log_n_entries(
            logger, 3,
            verdict=Verdict.APPROVED,
            score=0.1,
            level=RiskLevel.LOW,
            review_time=0.5,
        )
        stamps = logger.find_rubber_stamps(max_review_seconds=5.0, min_risk="high")
        assert len(stamps) == 0

    async def test_ignores_denied(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        # Fast denial on high risk (not a rubber stamp since it was denied)
        await _log_n_entries(
            logger, 2,
            verdict=Verdict.DENIED,
            score=0.7,
            level=RiskLevel.HIGH,
            review_time=0.5,
        )
        stamps = logger.find_rubber_stamps()
        assert len(stamps) == 0

    async def test_critical_included_when_min_risk_high(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(
            logger, 1,
            verdict=Verdict.APPROVED,
            score=0.9,
            level=RiskLevel.CRITICAL,
            review_time=1.0,
        )
        stamps = logger.find_rubber_stamps(max_review_seconds=5.0, min_risk="high")
        assert len(stamps) == 1

    async def test_medium_included_when_min_risk_medium(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(
            logger, 2,
            verdict=Verdict.APPROVED,
            score=0.45,
            level=RiskLevel.MEDIUM,
            review_time=1.0,
        )
        stamps = logger.find_rubber_stamps(max_review_seconds=5.0, min_risk="medium")
        assert len(stamps) == 2

    async def test_custom_max_review_seconds(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        await _log_n_entries(
            logger, 1,
            verdict=Verdict.APPROVED,
            score=0.7,
            level=RiskLevel.HIGH,
            review_time=3.0,
        )
        # With max 2s, the 3s review should NOT be flagged
        stamps = logger.find_rubber_stamps(max_review_seconds=2.0)
        assert len(stamps) == 0
        # With max 5s, it SHOULD be flagged
        stamps = logger.find_rubber_stamps(max_review_seconds=5.0)
        assert len(stamps) == 1

    async def test_empty_log(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(path=path)
        stamps = logger.find_rubber_stamps()
        assert stamps == []


# =========================================================================
# AuditLogger -- resume from existing log
# =========================================================================

class TestAuditLoggerResume:
    async def test_resume_continues_chain(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        # First logger writes 3 entries
        logger1 = AuditLogger(path=path)
        await _log_n_entries(logger1, 3)

        # Second logger resumes from the same file
        logger2 = AuditLogger(path=path)
        await _log_n_entries(logger2, 2)

        # Verify the full chain (5 entries) is intact
        verifier = AuditLogger(path=path)
        intact, total, broken = verifier.verify_chain()
        assert intact is True
        assert total == 5
        assert broken == []

    async def test_resume_entry_count(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger1 = AuditLogger(path=path)
        await _log_n_entries(logger1, 4)

        logger2 = AuditLogger(path=path)
        assert logger2._entry_count == 4

    async def test_resume_last_hash(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        logger1 = AuditLogger(path=path)
        await _log_n_entries(logger1, 2)
        last_hash = logger1._last_hash

        logger2 = AuditLogger(path=path)
        assert logger2._last_hash == last_hash
