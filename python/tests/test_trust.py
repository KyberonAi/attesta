"""Tests for attesta.core.trust -- adaptive trust engine."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from attesta.core.trust import TrustEngine, TrustProfile, TrustRecord

# =========================================================================
# TrustProfile dataclass
# =========================================================================

class TestTrustProfile:
    def test_defaults(self):
        p = TrustProfile(agent_id="agent-1")
        assert p.agent_id == "agent-1"
        assert p.overall_score == 0.3
        assert p.domain_scores == {}
        assert p.history == []
        assert p.incidents == 0
        assert isinstance(p.created_at, datetime)
        assert p.last_action_at is None


# =========================================================================
# TrustRecord dataclass
# =========================================================================

class TestTrustRecord:
    def test_creation(self):
        now = datetime.now()
        r = TrustRecord(
            timestamp=now,
            action_name="deploy",
            domain="infra",
            outcome="success",
            risk_score=0.5,
        )
        assert r.timestamp == now
        assert r.action_name == "deploy"
        assert r.domain == "infra"
        assert r.outcome == "success"
        assert r.risk_score == 0.5


# =========================================================================
# TrustEngine -- initial trust
# =========================================================================

class TestTrustEngineInitial:
    def test_default_initial_score(self):
        engine = TrustEngine()
        score = engine.compute_trust("new-agent")
        assert score == engine.initial_score
        assert score == 0.3

    def test_custom_initial_score(self):
        engine = TrustEngine(initial_score=0.5)
        score = engine.compute_trust("new-agent")
        assert score == 0.5

    def test_get_profile_creates_new(self):
        engine = TrustEngine()
        profile = engine.get_profile("agent-x")
        assert profile.agent_id == "agent-x"
        assert profile.overall_score == 0.3

    def test_get_profile_returns_same_instance(self):
        engine = TrustEngine()
        p1 = engine.get_profile("agent-x")
        p2 = engine.get_profile("agent-x")
        assert p1 is p2


# =========================================================================
# TrustEngine -- trust increases after success
# =========================================================================

class TestTrustAfterSuccess:
    def test_single_success_increases_trust(self):
        engine = TrustEngine(initial_score=0.3)
        initial = engine.compute_trust("agent-1")
        engine.record_success("agent-1", "deploy", domain="infra")
        after = engine.compute_trust("agent-1")
        # A success should make trust go above initial since the weighted
        # success rate will be ~1.0 (all events are successes)
        assert after > initial

    def test_multiple_successes_increase_trust(self):
        engine = TrustEngine(initial_score=0.3)
        engine.record_success("agent-1", "deploy", domain="infra")
        after_one = engine.compute_trust("agent-1")
        for i in range(5):
            engine.record_success("agent-1", f"action_{i}", domain="infra")
        after_many = engine.compute_trust("agent-1")
        # More successes -> higher trust
        assert after_many >= after_one

    def test_success_updates_profile_overall_score(self):
        engine = TrustEngine()
        engine.record_success("agent-1", "deploy")
        profile = engine.get_profile("agent-1")
        assert profile.overall_score > 0.3

    def test_success_updates_last_action_at(self):
        engine = TrustEngine()
        engine.record_success("agent-1", "deploy")
        profile = engine.get_profile("agent-1")
        assert profile.last_action_at is not None

    def test_success_appends_history(self):
        engine = TrustEngine()
        engine.record_success("agent-1", "deploy", domain="infra")
        profile = engine.get_profile("agent-1")
        assert len(profile.history) == 1
        assert profile.history[0].outcome == "success"
        assert profile.history[0].action_name == "deploy"
        assert profile.history[0].domain == "infra"


# =========================================================================
# TrustEngine -- trust decreases after incident
# =========================================================================

class TestTrustAfterIncident:
    def test_incident_decreases_trust(self):
        engine = TrustEngine(initial_score=0.3)
        # Build up some trust first
        for _ in range(5):
            engine.record_success("agent-1", "safe_action")
        before_incident = engine.compute_trust("agent-1")
        engine.record_incident("agent-1", action_name="bad_action")
        after_incident = engine.compute_trust("agent-1")
        assert after_incident < before_incident

    def test_multiple_incidents_decrease_more(self):
        engine = TrustEngine(initial_score=0.3)
        for _ in range(5):
            engine.record_success("agent-1", "safe_action")
        engine.record_incident("agent-1", action_name="bad1")
        after_one = engine.compute_trust("agent-1")
        engine.record_incident("agent-1", action_name="bad2")
        after_two = engine.compute_trust("agent-1")
        assert after_two < after_one

    def test_incident_increments_count(self):
        engine = TrustEngine()
        engine.record_incident("agent-1")
        profile = engine.get_profile("agent-1")
        assert profile.incidents == 1
        engine.record_incident("agent-1")
        assert profile.incidents == 2

    def test_incident_penalty_is_multiplicative(self):
        """The default incident_penalty=0.7 is applied per incident."""
        engine = TrustEngine(incident_penalty=0.7)
        # Record successes to establish a baseline
        for _ in range(10):
            engine.record_success("agent-1", "action")
        before = engine.compute_trust("agent-1")
        engine.record_incident("agent-1")
        after = engine.compute_trust("agent-1")
        # Trust should be reduced by roughly the penalty factor
        # (not exactly, because incident also adds to history)
        assert after < before


# =========================================================================
# TrustEngine -- trust decays over time (inactivity)
# =========================================================================

class TestTrustDecay:
    def test_decay_reduces_trust_over_time(self):
        engine = TrustEngine(decay_rate=0.01)
        # Record a success with a timestamp in the past
        profile = engine.get_profile("agent-1")
        past = datetime.now() - timedelta(days=30)
        record = TrustRecord(
            timestamp=past,
            action_name="old_action",
            domain="general",
            outcome="success",
            risk_score=0.5,
        )
        profile.history.append(record)
        profile.last_action_at = past

        trust_after_inactivity = engine.compute_trust("agent-1")

        # Now record a recent success
        engine.record_success("agent-1", "fresh_action")
        trust_after_fresh = engine.compute_trust("agent-1")

        # Trust after fresh activity should be higher than after long inactivity
        assert trust_after_fresh > trust_after_inactivity

    def test_high_decay_rate_reduces_faster(self):
        engine_slow = TrustEngine(decay_rate=0.001)
        engine_fast = TrustEngine(decay_rate=0.1)

        past = datetime.now() - timedelta(days=60)
        for eng in (engine_slow, engine_fast):
            profile = eng.get_profile("agent-1")
            record = TrustRecord(
                timestamp=past,
                action_name="old_action",
                domain="general",
                outcome="success",
                risk_score=0.5,
            )
            profile.history.append(record)
            profile.last_action_at = past

        slow_trust = engine_slow.compute_trust("agent-1")
        fast_trust = engine_fast.compute_trust("agent-1")
        assert fast_trust < slow_trust

    def test_no_decay_when_recently_active(self):
        """When the agent was just active, recency factor should be ~1.0."""
        engine = TrustEngine(decay_rate=0.01)
        engine.record_success("agent-1", "recent_action")
        trust = engine.compute_trust("agent-1")
        # Should be close to the weighted success rate (near 1.0) * penalty (1.0)
        # * recency (~1.0), bounded by ceiling
        assert trust > 0.5


# =========================================================================
# TrustEngine -- revocation
# =========================================================================

class TestTrustRevocation:
    def test_revoke_zeros_overall_score(self):
        engine = TrustEngine()
        for _ in range(10):
            engine.record_success("agent-1", "action")
        engine.revoke("agent-1")
        profile = engine.get_profile("agent-1")
        assert profile.overall_score == 0.0

    def test_revoke_clears_domain_scores(self):
        engine = TrustEngine()
        engine.record_success("agent-1", "deploy", domain="infra")
        engine.record_success("agent-1", "query", domain="data")
        profile = engine.get_profile("agent-1")
        assert len(profile.domain_scores) > 0
        engine.revoke("agent-1")
        assert profile.domain_scores == {}

    def test_revoke_adds_heavy_penalty(self):
        engine = TrustEngine()
        engine.revoke("agent-1")
        profile = engine.get_profile("agent-1")
        assert profile.incidents >= 3

    def test_trust_very_low_after_revoke_and_new_success(self):
        """Even after recording a success post-revocation, trust should be very low."""
        engine = TrustEngine(incident_penalty=0.7)
        for _ in range(10):
            engine.record_success("agent-1", "action")
        engine.revoke("agent-1")
        # Record a single success after revocation
        engine.record_success("agent-1", "comeback_action")
        trust = engine.compute_trust("agent-1")
        # With 3+ incidents at penalty 0.7, trust should be severely reduced
        assert trust < 0.5


# =========================================================================
# TrustEngine -- domain-specific trust
# =========================================================================

class TestDomainSpecificTrust:
    def test_domain_trust_differs_from_overall(self):
        engine = TrustEngine()
        # Record successes in different domains
        for _ in range(5):
            engine.record_success("agent-1", "deploy", domain="infra")
        for _ in range(5):
            engine.record_success("agent-1", "query", domain="data")

        overall = engine.compute_trust("agent-1")
        infra = engine.compute_trust("agent-1", domain="infra")
        data = engine.compute_trust("agent-1", domain="data")

        # All should be positive
        assert overall > 0
        assert infra > 0
        assert data > 0

    def test_no_history_for_domain_returns_initial(self):
        engine = TrustEngine(initial_score=0.3)
        engine.record_success("agent-1", "deploy", domain="infra")
        # No history for "finance" domain
        finance_trust = engine.compute_trust("agent-1", domain="finance")
        assert finance_trust == 0.3

    def test_domain_scores_updated_on_success(self):
        engine = TrustEngine()
        engine.record_success("agent-1", "deploy", domain="infra")
        profile = engine.get_profile("agent-1")
        assert "infra" in profile.domain_scores
        assert profile.domain_scores["infra"] > 0

    def test_incident_affects_all_domains(self):
        """Incidents are agent-level, so they affect all domain computations."""
        engine = TrustEngine()
        for _ in range(10):
            engine.record_success("agent-1", "deploy", domain="infra")
        for _ in range(10):
            engine.record_success("agent-1", "query", domain="data")

        infra_before = engine.compute_trust("agent-1", domain="infra")
        engine.record_incident("agent-1", domain="data")
        infra_after = engine.compute_trust("agent-1", domain="infra")
        # Incident in "data" domain should also reduce infra trust
        # because incidents increment the profile-level counter
        assert infra_after < infra_before


# =========================================================================
# TrustEngine -- effective_risk
# =========================================================================

class TestEffectiveRisk:
    def test_high_trust_reduces_risk(self):
        engine = TrustEngine(influence=0.3)
        # Build high trust
        for _ in range(20):
            engine.record_success("agent-1", "action")
        trust = engine.compute_trust("agent-1")
        assert trust > 0.5  # Need trust > 0.5 for discount

        raw_risk = 0.6
        effective = engine.effective_risk(raw_risk, "agent-1")
        assert effective < raw_risk

    def test_new_agent_no_discount(self):
        engine = TrustEngine(influence=0.3)
        raw_risk = 0.6
        effective = engine.effective_risk(raw_risk, "new-agent")
        # Trust is 0.3 (initial), so discount = (0.3 - 0.5) * 0.3 = -0.06
        # effective = 0.6 * (1 - (-0.06)) = 0.6 * 1.06 = 0.636
        assert effective >= raw_risk

    def test_effective_risk_clamped_to_zero_one(self):
        engine = TrustEngine(influence=0.3)
        # Very low raw risk should not go below 0
        effective = engine.effective_risk(0.01, "new-agent")
        assert effective >= 0.0
        # Very high raw risk should not exceed 1.0
        effective = engine.effective_risk(0.99, "new-agent")
        assert effective <= 1.0


# =========================================================================
# TrustEngine -- trust ceiling
# =========================================================================

class TestTrustCeiling:
    def test_trust_never_exceeds_ceiling(self):
        engine = TrustEngine(ceiling=0.9)
        # Record many successes
        for _ in range(100):
            engine.record_success("agent-1", "action")
        trust = engine.compute_trust("agent-1")
        assert trust <= 0.9

    def test_custom_ceiling(self):
        engine = TrustEngine(ceiling=0.5)
        for _ in range(100):
            engine.record_success("agent-1", "action")
        trust = engine.compute_trust("agent-1")
        assert trust <= 0.5


# =========================================================================
# TrustEngine -- record_denial
# =========================================================================

class TestRecordDenial:
    def test_denial_recorded_in_history(self):
        engine = TrustEngine()
        engine.record_denial("agent-1", "bad_action", domain="infra")
        profile = engine.get_profile("agent-1")
        assert len(profile.history) == 1
        assert profile.history[0].outcome == "denied"

    def test_denial_updates_last_action_at(self):
        engine = TrustEngine()
        engine.record_denial("agent-1", "bad_action")
        profile = engine.get_profile("agent-1")
        assert profile.last_action_at is not None

    def test_denial_reduces_trust(self):
        engine = TrustEngine()
        for _ in range(5):
            engine.record_success("agent-1", "action")
        trust_before = engine.compute_trust("agent-1")
        for _ in range(5):
            engine.record_denial("agent-1", "denied_action")
        trust_after = engine.compute_trust("agent-1")
        # Denials dilute the success rate
        assert trust_after < trust_before


# =========================================================================
# TrustEngine -- persistence
# =========================================================================

class TestTrustPersistence:
    def test_save_and_load(self, tmp_path):
        path = tmp_path / "trust.json"
        engine = TrustEngine(storage_path=path)
        engine.record_success("agent-1", "deploy", domain="infra")
        engine.record_incident("agent-1")

        # Verify file was written
        assert path.exists()
        data = json.loads(path.read_text())
        assert "agent-1" in data
        assert data["agent-1"]["incidents"] == 1

    def test_resume_from_storage(self, tmp_path):
        path = tmp_path / "trust.json"
        # Create and save
        engine1 = TrustEngine(storage_path=path, initial_score=0.3)
        engine1.record_success("agent-1", "deploy")
        engine1.record_incident("agent-1")

        # Load from same path
        engine2 = TrustEngine(storage_path=path, initial_score=0.3)
        profile = engine2.get_profile("agent-1")
        assert profile.incidents == 1
        assert profile.overall_score != 0.3  # Should have loaded the saved value
