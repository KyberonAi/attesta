"""Tests for new attesta features: config unification, trust wiring, smart
renderer detection, and configurable sync_timeout.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from attesta.core.gate import Attesta, _DefaultRenderer, _detect_renderer, gate
from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    RiskLevel,
    Verdict,
)

# =========================================================================
# Mock helpers
# =========================================================================


class ApproveAllRenderer:
    """Mock renderer that approves every action."""

    async def render_approval(self, ctx: ActionContext, risk: RiskAssessment) -> Verdict:
        return Verdict.APPROVED

    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        return ChallengeResult(
            passed=True,
            challenge_type=challenge_type,
            responder="test-auto",
        )

    async def render_info(self, message: str) -> None:
        pass

    async def render_auto_approved(self, ctx: ActionContext, risk: RiskAssessment) -> None:
        pass


class DenyAllRenderer:
    """Mock renderer that denies every action."""

    async def render_approval(self, ctx: ActionContext, risk: RiskAssessment) -> Verdict:
        return Verdict.DENIED

    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        return ChallengeResult(
            passed=False,
            challenge_type=challenge_type,
            responder="test-deny",
        )

    async def render_info(self, message: str) -> None:
        pass

    async def render_auto_approved(self, ctx: ActionContext, risk: RiskAssessment) -> None:
        pass


class SlowRenderer:
    """Mock renderer that times out challenge flows."""

    async def render_approval(self, ctx: ActionContext, risk: RiskAssessment) -> Verdict:
        await asyncio.sleep(9999)
        return Verdict.APPROVED  # pragma: no cover

    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        await asyncio.sleep(9999)
        return ChallengeResult(  # pragma: no cover
            passed=True,
            challenge_type=challenge_type,
        )

    async def render_info(self, message: str) -> None:
        pass

    async def render_auto_approved(self, ctx: ActionContext, risk: RiskAssessment) -> None:
        pass


class FakeTrustEngine:
    """Simple test double for the TrustEngine with controllable discount."""

    def __init__(self, discount: float = 0.5) -> None:
        self.discount = discount
        self.successes: list[tuple[str, str]] = []
        self.denials: list[tuple[str, str]] = []

    def effective_risk(
        self,
        raw_risk: float,
        agent_id: str,
        domain: str | None = None,
    ) -> float:
        return raw_risk * self.discount

    def record_success(
        self,
        agent_id: str,
        action_name: str,
        domain: str = "general",
        risk_score: float = 0.5,
    ) -> None:
        self.successes.append((agent_id, action_name))

    def record_denial(
        self,
        agent_id: str,
        action_name: str,
        domain: str = "general",
        risk_score: float = 0.5,
    ) -> None:
        self.denials.append((agent_id, action_name))


# =========================================================================
# 1. Config Unification -- Policy methods
# =========================================================================


class TestPolicyToChallengeMap:
    """Verify Policy.to_challenge_map() produces the correct mapping."""

    def test_default_without_multi_party(self):
        """When require_multi_party has no entry > 1 for critical,
        CRITICAL maps to TEACH_BACK."""
        from attesta.config.loader import Policy

        policy = Policy(require_multi_party={})
        cmap = policy.to_challenge_map()
        assert cmap[RiskLevel.LOW] == ChallengeType.AUTO_APPROVE
        assert cmap[RiskLevel.MEDIUM] == ChallengeType.CONFIRM
        assert cmap[RiskLevel.HIGH] == ChallengeType.QUIZ
        assert cmap[RiskLevel.CRITICAL] == ChallengeType.TEACH_BACK

    def test_with_multi_party(self):
        """When require_multi_party specifies critical >= 2,
        CRITICAL maps to MULTI_PARTY."""
        from attesta.config.loader import Policy

        policy = Policy(require_multi_party={"critical": 2})
        cmap = policy.to_challenge_map()
        assert cmap[RiskLevel.CRITICAL] == ChallengeType.MULTI_PARTY

    def test_default_policy_has_multi_party_by_default(self):
        """The default Policy() has require_multi_party={'critical': 2},
        so CRITICAL -> MULTI_PARTY."""
        from attesta.config.loader import Policy

        policy = Policy()
        cmap = policy.to_challenge_map()
        assert cmap[RiskLevel.CRITICAL] == ChallengeType.MULTI_PARTY

    def test_all_risk_levels_present(self):
        """to_challenge_map() returns an entry for every RiskLevel."""
        from attesta.config.loader import Policy

        policy = Policy()
        cmap = policy.to_challenge_map()
        for level in RiskLevel:
            assert level in cmap


class TestPolicyToTrustEngineKwargs:
    """Verify Policy.to_trust_engine_kwargs() returns the right keys/values."""

    def test_custom_trust_settings(self):
        from attesta.config.loader import Policy

        policy = Policy(
            trust_initial=0.5,
            trust_ceiling=0.8,
            trust_decay_rate=0.02,
            trust_influence=0.4,
        )
        kwargs = policy.to_trust_engine_kwargs()
        assert kwargs == {
            "initial_score": 0.5,
            "ceiling": 0.8,
            "decay_rate": 0.02,
            "influence": 0.4,
        }

    def test_default_trust_settings(self):
        from attesta.config.loader import Policy

        policy = Policy()
        kwargs = policy.to_trust_engine_kwargs()
        assert kwargs == {
            "initial_score": 0.3,
            "ceiling": 0.9,
            "decay_rate": 0.01,
            "influence": 0.3,
        }


class TestPolicyMinReviewTime:
    """Verify Policy.min_review_time() returns the configured values."""

    def test_default_review_times(self):
        from attesta.config.loader import Policy

        policy = Policy()
        assert policy.min_review_time(RiskLevel.LOW) == 0
        assert policy.min_review_time(RiskLevel.MEDIUM) == 3
        assert policy.min_review_time(RiskLevel.HIGH) == 10
        assert policy.min_review_time(RiskLevel.CRITICAL) == 30

    def test_custom_review_times(self):
        from attesta.config.loader import Policy

        policy = Policy(minimum_review_seconds={"medium": 5, "high": 15})
        assert policy.min_review_time(RiskLevel.MEDIUM) == 5
        assert policy.min_review_time(RiskLevel.HIGH) == 15
        # Missing keys return 0
        assert policy.min_review_time(RiskLevel.LOW) == 0


# =========================================================================
# 1b. Attesta.from_config() -- rich and legacy formats
# =========================================================================


@pytest.mark.skipif(
    not __import__("importlib").util.find_spec("yaml"),
    reason="PyYAML not installed (pip install attesta[yaml])",
)
class TestAttestaFromConfig:
    """Verify Attesta.from_config() correctly handles rich and legacy YAML."""

    def test_rich_format(self, tmp_path):
        """Rich config with trust/policy sections sets up trust engine,
        policy object, and challenge map."""
        from attesta import Attesta

        config = tmp_path / "attesta.yaml"
        config.write_text(
            "trust:\n"
            "  influence: 0.4\n"
            "  ceiling: 0.85\n"
            "  initial_score: 0.4\n"
            "  decay_rate: 0.02\n"
            "policy:\n"
            "  minimum_review_seconds:\n"
            "    medium: 5\n"
            "    high: 15\n"
            "  require_multi_party:\n"
            "    critical: 2\n"
        )
        gk = Attesta.from_config(config)
        assert gk._trust_engine is not None
        assert gk._policy_obj is not None
        assert gk._challenge_map is not None
        assert gk._challenge_map[RiskLevel.CRITICAL] == ChallengeType.MULTI_PARTY

    def test_rich_format_missing_domain_fails_fast_by_default(self, tmp_path):
        """Missing configured domain preset raises a clear config error."""
        from attesta import Attesta

        config = tmp_path / "attesta.yaml"
        config.write_text("domain: nonexistent_domain_xyz_123\npolicy:\n  minimum_review_seconds:\n    medium: 3\n")
        with pytest.raises(ValueError, match="Configured domain profile was not found"):
            Attesta.from_config(config)

    def test_domain_only_config_treated_as_rich(self, tmp_path):
        """Top-level domain key should use rich config parsing path."""
        from attesta import Attesta

        config = tmp_path / "attesta.yaml"
        config.write_text("domain: nonexistent_domain_xyz_123\n")
        with pytest.raises(ValueError, match="Configured domain profile was not found"):
            Attesta.from_config(config)

    def test_missing_domain_can_be_opted_out(self, tmp_path):
        """domain_strict=false allows startup without a registered profile."""
        from attesta import Attesta

        config = tmp_path / "attesta.yaml"
        config.write_text(
            "domain: nonexistent_domain_xyz_123\n"
            "domain_strict: false\n"
            "policy:\n"
            "  minimum_review_seconds:\n"
            "    medium: 3\n"
        )
        gk = Attesta.from_config(config)
        assert gk._policy_obj is not None
        assert gk._policy_obj.domain_strict is False
        assert gk._risk_scorer is None

    def test_rich_format_trust_engine_params(self, tmp_path):
        """Trust engine created from rich config uses the YAML values."""
        from attesta import Attesta

        config = tmp_path / "attesta.yaml"
        config.write_text("trust:\n  influence: 0.4\n  ceiling: 0.85\n  initial_score: 0.4\n  decay_rate: 0.02\n")
        gk = Attesta.from_config(config)
        assert gk._trust_engine is not None
        assert gk._trust_engine.initial_score == 0.4
        assert gk._trust_engine.ceiling == 0.85

    def test_legacy_format(self, tmp_path):
        """Legacy flat config still works and does NOT create trust engine."""
        from attesta import Attesta

        config = tmp_path / "legacy.yaml"
        config.write_text(
            "default_environment: production\n"
            "min_review_seconds: 2.0\n"
            "challenge_map:\n"
            "  low: auto_approve\n"
            "  medium: confirm\n"
            "  high: quiz\n"
            "  critical: multi_party\n"
        )
        gk = Attesta.from_config(config)
        # Legacy format does NOT set up trust engine or policy object
        assert gk._trust_engine is None
        assert gk._policy_obj is None
        # But challenge map IS parsed
        assert gk._challenge_map is not None
        assert gk.policy["default_environment"] == "production"

    def test_file_not_found(self, tmp_path):
        """from_config() raises FileNotFoundError for missing files."""
        from attesta import Attesta

        with pytest.raises(FileNotFoundError):
            Attesta.from_config(tmp_path / "nonexistent.yaml")

    def test_rich_format_challenge_map_without_multi_party(self, tmp_path):
        """Rich config without multi-party maps CRITICAL to TEACH_BACK."""
        from attesta import Attesta

        config = tmp_path / "attesta.yaml"
        config.write_text("trust:\n  influence: 0.3\npolicy:\n  require_multi_party: {}\n")
        gk = Attesta.from_config(config)
        assert gk._challenge_map is not None
        assert gk._challenge_map[RiskLevel.CRITICAL] == ChallengeType.TEACH_BACK

    def test_rich_format_wires_fail_mode_escalate(self, tmp_path):
        """policy.fail_mode + policy.timeout_seconds affect runtime decisions."""
        from attesta import Attesta, AttestaDenied

        config = tmp_path / "attesta.yaml"
        config.write_text("policy:\n  fail_mode: escalate\n  timeout_seconds: 0.05\n")
        gk = Attesta.from_config(config)

        @gk.gate(risk="medium", renderer=SlowRenderer())
        def protected_action() -> str:
            return "should-not-run"

        with pytest.raises(AttestaDenied) as exc_info:
            protected_action()

        assert exc_info.value.result is not None
        assert exc_info.value.result.verdict == Verdict.ESCALATED
        assert exc_info.value.result.metadata["timed_out"] is True
        assert gk.policy["fail_mode"] == "escalate"
        assert gk.policy["timeout_seconds"] == 0.05

    def test_rich_format_wires_fail_mode_allow(self, tmp_path):
        """policy.fail_mode=allow permits execution after timeout."""
        from attesta import Attesta

        config = tmp_path / "attesta.yaml"
        config.write_text("policy:\n  fail_mode: allow\n  timeout_seconds: 0.05\n")
        gk = Attesta.from_config(config)

        @gk.gate(risk="high", renderer=SlowRenderer())
        def protected_action() -> str:
            return "ran"

        assert protected_action() == "ran"


# =========================================================================
# 2. Trust Engine Wiring in Attesta.evaluate()
# =========================================================================


class TestTrustEngineInAttesta:
    """Verify that Attesta correctly interacts with the trust engine."""

    async def test_trust_engine_adjusts_risk(self):
        """Trust discount reduces the risk score for non-CRITICAL actions."""
        trust = FakeTrustEngine(discount=0.3)  # reduces risk to 30%
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.HIGH,  # score=0.70
            trust_engine=trust,
        )
        ctx = ActionContext(function_name="deploy", agent_id="agent-1")
        result = await g.evaluate(ctx)
        # 0.70 * 0.3 = 0.21 -> LOW risk -> auto-approve
        assert result.risk_assessment.score == pytest.approx(0.21, abs=0.01)
        assert result.risk_assessment.level == RiskLevel.LOW

    async def test_trust_never_downgrades_critical(self):
        """CRITICAL risk must stay CRITICAL regardless of trust discount."""
        trust = FakeTrustEngine(discount=0.1)  # would reduce to 0.09
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.CRITICAL,  # score=0.90
            trust_engine=trust,
        )
        ctx = ActionContext(function_name="nuke", agent_id="agent-1")
        result = await g.evaluate(ctx)
        # CRITICAL must stay CRITICAL -- trust does NOT apply
        assert result.risk_assessment.level == RiskLevel.CRITICAL
        assert result.risk_assessment.score == 0.90

    async def test_trust_records_success_on_approval(self):
        """After an approved action, the trust engine records a success."""
        trust = FakeTrustEngine(discount=1.0)  # no adjustment
        g = Attesta(renderer=ApproveAllRenderer(), trust_engine=trust)
        ctx = ActionContext(function_name="read_data", agent_id="agent-1")
        result = await g.evaluate(ctx)
        assert result.verdict == Verdict.APPROVED
        assert len(trust.successes) == 1
        assert trust.successes[0][0] == "agent-1"

    async def test_trust_records_denial(self):
        """After a denied action, the trust engine records a denial."""
        trust = FakeTrustEngine(discount=1.0)
        g = Attesta(
            renderer=DenyAllRenderer(),
            risk_override=RiskLevel.MEDIUM,  # needs confirmation -> denied
            trust_engine=trust,
        )
        ctx = ActionContext(function_name="deploy", agent_id="agent-1")
        result = await g.evaluate(ctx)
        assert result.verdict == Verdict.DENIED
        assert len(trust.denials) == 1
        assert trust.denials[0][0] == "agent-1"

    async def test_trust_skipped_without_agent_id(self):
        """When no agent_id is set, trust adjustment is skipped entirely."""
        trust = FakeTrustEngine(discount=0.1)
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.HIGH,
            trust_engine=trust,
        )
        ctx = ActionContext(function_name="deploy")  # no agent_id
        result = await g.evaluate(ctx)
        # Trust should be skipped - risk stays at HIGH level (0.70)
        assert result.risk_assessment.score == 0.70
        assert result.risk_assessment.level == RiskLevel.HIGH

    async def test_trust_no_recording_without_agent_id(self):
        """Without agent_id, no successes or denials are recorded."""
        trust = FakeTrustEngine(discount=1.0)
        g = Attesta(renderer=ApproveAllRenderer(), trust_engine=trust)
        ctx = ActionContext(function_name="read_data")  # no agent_id
        await g.evaluate(ctx)
        assert len(trust.successes) == 0
        assert len(trust.denials) == 0

    async def test_trust_adjustment_adds_factor(self):
        """When trust adjusts risk, a trust_adjustment factor is added."""
        trust = FakeTrustEngine(discount=0.5)
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.HIGH,  # score=0.70
            trust_engine=trust,
        )
        ctx = ActionContext(function_name="deploy", agent_id="agent-1")
        result = await g.evaluate(ctx)
        factor_names = [f.name for f in result.risk_assessment.factors]
        assert "trust_adjustment" in factor_names

    async def test_trust_medium_stays_medium(self):
        """Discount that keeps score within MEDIUM range preserves the level."""
        trust = FakeTrustEngine(discount=1.0)  # no change
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.MEDIUM,  # score=0.45
            trust_engine=trust,
        )
        ctx = ActionContext(function_name="update", agent_id="agent-1")
        result = await g.evaluate(ctx)
        # 0.45 * 1.0 = 0.45 -> still MEDIUM
        assert result.risk_assessment.level == RiskLevel.MEDIUM


# =========================================================================
# 3. Smart Default Renderer Detection
# =========================================================================


class TestDetectRenderer:
    """Verify _detect_renderer() picks the right renderer for the environment."""

    def test_non_tty_returns_default_renderer(self):
        """When stdin is not a TTY, the default (auto-approve) renderer is used."""
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            renderer = _detect_renderer()
            assert isinstance(renderer, _DefaultRenderer)

    def test_tty_returns_a_renderer(self):
        """When stdin IS a TTY, a renderer is returned (exact type depends
        on whether rich is installed)."""
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            renderer = _detect_renderer()
            # Should be TerminalRenderer if rich is installed,
            # or _DefaultRenderer otherwise.  Either way it is not None.
            assert renderer is not None

    def test_tty_without_rich_falls_back(self):
        """If stdin is a TTY but rich is not importable, falls back to
        _DefaultRenderer."""
        with (
            patch("sys.stdin") as mock_stdin,
            patch.dict("sys.modules", {"attesta.renderers.terminal": None}),
        ):
            mock_stdin.isatty.return_value = True
            renderer = _detect_renderer()
            assert isinstance(renderer, _DefaultRenderer)


# =========================================================================
# 4. Configurable sync_timeout
# =========================================================================


class TestSyncTimeout:
    """Verify the sync_timeout parameter is accepted by @gate."""

    def test_sync_timeout_parameter_accepted(self):
        """@gate(sync_timeout=60.0) creates a gate without errors."""

        @gate(sync_timeout=60.0)
        def my_func():
            return "ok"

        assert hasattr(my_func, "__gate__")
        assert isinstance(my_func.__gate__, Attesta)

    def test_sync_timeout_default(self):
        """@gate() without sync_timeout still works (defaults to 300)."""

        @gate()
        def my_func():
            return "ok"

        assert hasattr(my_func, "__gate__")

    def test_sync_timeout_with_other_params(self):
        """sync_timeout can be combined with other decorator parameters."""

        @gate(sync_timeout=120.0, renderer=ApproveAllRenderer(), risk="low")
        def my_func():
            return "ok"

        result = my_func()
        assert result == "ok"

    def test_sync_timeout_zero(self):
        """sync_timeout=0 is accepted (means wait indefinitely)."""

        @gate(sync_timeout=0)
        def my_func():
            return "ok"

        assert hasattr(my_func, "__gate__")
