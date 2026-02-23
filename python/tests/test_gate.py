"""Tests for attesta.core.gate -- Attesta class and @gate decorator."""

from __future__ import annotations

import asyncio

import pytest

from attesta.core.gate import Attesta, AttestaDenied, gate
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
# Mock renderer helpers
# =========================================================================

class ApproveAllRenderer:
    """Mock renderer that approves every action."""

    async def render_approval(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> Verdict:
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

    async def render_auto_approved(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> None:
        pass


class DenyAllRenderer:
    """Mock renderer that denies every action."""

    async def render_approval(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> Verdict:
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

    async def render_auto_approved(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> None:
        pass


class SlowRenderer:
    """Mock renderer that never returns challenge responses."""

    async def render_approval(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> Verdict:
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

    async def render_auto_approved(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> None:
        pass


class RecordingAuditLogger:
    """Mock audit logger that records calls."""

    def __init__(self):
        self.entries: list[tuple[ActionContext, ApprovalResult]] = []

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        self.entries.append((ctx, result))
        return f"test-audit-{len(self.entries)}"


# =========================================================================
# AttestaDenied exception
# =========================================================================

class TestAttestaDenied:
    def test_default_message(self):
        exc = AttestaDenied()
        assert str(exc) == "Action denied by attesta"
        assert exc.result is None

    def test_custom_message(self):
        exc = AttestaDenied("custom denial")
        assert str(exc) == "custom denial"

    def test_carries_result(self):
        ra = RiskAssessment(score=0.9, level=RiskLevel.CRITICAL)
        result = ApprovalResult(verdict=Verdict.DENIED, risk_assessment=ra)
        exc = AttestaDenied("denied", result=result)
        assert exc.result is result
        assert exc.result.verdict is Verdict.DENIED

    def test_is_exception(self):
        assert issubclass(AttestaDenied, Exception)


# =========================================================================
# Attesta.evaluate() -- core pipeline
# =========================================================================

class TestAttestaEvaluate:
    async def test_auto_approve_for_low_risk(self):
        """Low risk -> AUTO_APPROVE challenge -> approved without interaction."""
        g = Attesta(renderer=ApproveAllRenderer())
        ctx = ActionContext(function_name="get_user")
        result = await g.evaluate(ctx)
        assert result.verdict is Verdict.APPROVED

    async def test_denied_when_renderer_denies(self):
        """When the renderer returns a failed challenge, verdict is DENIED."""
        # Force high risk so we go through the challenge path
        g = Attesta(
            renderer=DenyAllRenderer(),
            risk_override=RiskLevel.HIGH,
        )
        ctx = ActionContext(function_name="deploy")
        result = await g.evaluate(ctx)
        assert result.verdict is Verdict.DENIED

    async def test_risk_override_sets_level(self):
        """risk_override bypasses the scorer."""
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.CRITICAL,
        )
        ctx = ActionContext(function_name="get_user")
        result = await g.evaluate(ctx)
        assert result.risk_assessment.level is RiskLevel.CRITICAL
        assert result.risk_assessment.scorer_name == "override"

    async def test_risk_override_from_string(self):
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override="high",
        )
        ctx = ActionContext(function_name="anything")
        result = await g.evaluate(ctx)
        assert result.risk_assessment.level is RiskLevel.HIGH

    async def test_risk_hints_merged(self):
        """Extra risk hints should be merged into the ActionContext."""
        audit = RecordingAuditLogger()
        g = Attesta(
            renderer=ApproveAllRenderer(),
            audit_logger=audit,
            risk_hints={"production": True},
        )
        ctx = ActionContext(function_name="deploy")
        await g.evaluate(ctx)
        # After evaluate, the ctx should have the merged hints
        assert ctx.hints.get("production") is True

    async def test_audit_entry_id_set(self):
        audit = RecordingAuditLogger()
        g = Attesta(renderer=ApproveAllRenderer(), audit_logger=audit)
        ctx = ActionContext(function_name="do_thing")
        result = await g.evaluate(ctx)
        assert result.audit_entry_id is not None
        assert result.audit_entry_id.startswith("test-audit-")

    async def test_review_time_recorded(self):
        g = Attesta(renderer=ApproveAllRenderer())
        ctx = ActionContext(function_name="do_thing")
        result = await g.evaluate(ctx)
        assert result.review_time_seconds >= 0.0

    async def test_challenge_result_present_for_non_auto(self):
        """When risk is not LOW (not AUTO_APPROVE), a challenge result is returned."""
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.MEDIUM,
        )
        ctx = ActionContext(function_name="update_config")
        result = await g.evaluate(ctx)
        # MEDIUM risk -> CONFIRM challenge
        assert result.challenge_result is not None
        assert result.challenge_result.challenge_type is ChallengeType.CONFIRM
        assert result.challenge_result.passed is True

    async def test_challenge_result_none_for_auto_approve(self):
        """When risk is LOW, challenge type is AUTO_APPROVE, no challenge result."""
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.LOW,
        )
        ctx = ActionContext(function_name="get_status")
        result = await g.evaluate(ctx)
        assert result.challenge_result is None

    async def test_custom_challenge_map(self):
        """A custom challenge map overrides the default."""
        custom_map = {
            RiskLevel.LOW: ChallengeType.CONFIRM,  # normally AUTO_APPROVE
            RiskLevel.MEDIUM: ChallengeType.QUIZ,
            RiskLevel.HIGH: ChallengeType.MULTI_PARTY,
            RiskLevel.CRITICAL: ChallengeType.MULTI_PARTY,
        }
        g = Attesta(
            renderer=ApproveAllRenderer(),
            risk_override=RiskLevel.LOW,
            challenge_map=custom_map,
        )
        ctx = ActionContext(function_name="get_user")
        result = await g.evaluate(ctx)
        # With custom map, LOW -> CONFIRM, so challenge_result should exist
        assert result.challenge_result is not None
        assert result.challenge_result.challenge_type is ChallengeType.CONFIRM

    async def test_audit_failure_does_not_raise(self):
        """If the audit logger raises, the gate should log a warning but not crash."""

        class FailingAudit:
            async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
                raise RuntimeError("disk full")

        g = Attesta(renderer=ApproveAllRenderer(), audit_logger=FailingAudit())
        ctx = ActionContext(function_name="do_thing")
        # Should not raise
        result = await g.evaluate(ctx)
        assert result.verdict is Verdict.APPROVED
        assert result.audit_entry_id is None


# =========================================================================
# @gate decorator -- sync functions
# =========================================================================

class TestAttestaDecoratorSync:
    def test_bare_decorator(self):
        """@gate without parentheses wraps a sync function."""

        @gate
        def add(a: int, b: int) -> int:
            return a + b

        # Default renderer auto-approves, default scorer scores low
        result = add(2, 3)
        assert result == 5

    def test_empty_parens_decorator(self):
        """@gate() with empty parentheses wraps a sync function."""

        @gate()
        def add(a: int, b: int) -> int:
            return a + b

        result = add(2, 3)
        assert result == 5

    def test_preserves_function_name(self):
        @gate
        def my_special_func():
            pass

        assert my_special_func.__name__ == "my_special_func"

    def test_fail_mode_allow_allows_sync_execution_after_timeout(self):
        @gate(
            risk="high",
            renderer=SlowRenderer(),
            approval_timeout_seconds=0.05,
            fail_mode="allow",
        )
        def do_work() -> str:
            return "executed"

        assert do_work() == "executed"

    def test_preserves_docstring(self):
        @gate
        def documented():
            """This is a docstring."""
            pass

        assert documented.__doc__ == "This is a docstring."

    def test_gate_instance_attached(self):
        """The Attesta instance is accessible as __gate__ on the wrapper."""

        @gate
        def some_func():
            pass

        assert hasattr(some_func, "__gate__")
        assert isinstance(some_func.__gate__, Attesta)

    def test_with_renderer_override(self):
        """@gate(renderer=...) allows overriding the renderer."""

        @gate(renderer=ApproveAllRenderer())
        def compute(x: int) -> int:
            return x * 2

        assert compute(5) == 10

    def test_denied_raises_exception(self):
        """When the renderer denies, AttestaDenied is raised."""

        @gate(renderer=DenyAllRenderer(), risk="high")
        def dangerous_action():
            return "should not reach here"

        with pytest.raises(AttestaDenied) as exc_info:
            dangerous_action()

        assert exc_info.value.result is not None
        assert exc_info.value.result.verdict is Verdict.DENIED

    def test_denied_exception_carries_result(self):

        @gate(renderer=DenyAllRenderer(), risk="critical")
        def nuke():
            pass

        with pytest.raises(AttestaDenied) as exc_info:
            nuke()

        result = exc_info.value.result
        assert isinstance(result, ApprovalResult)
        assert result.risk_assessment.level is RiskLevel.CRITICAL

    def test_risk_override_string(self):
        """risk='high' (string) is accepted and parsed."""

        @gate(renderer=DenyAllRenderer(), risk="high")
        def deploy():
            pass

        with pytest.raises(AttestaDenied) as exc_info:
            deploy()

        assert exc_info.value.result.risk_assessment.level is RiskLevel.HIGH

    def test_risk_override_enum(self):
        """risk=RiskLevel.HIGH (enum) is accepted."""

        @gate(renderer=DenyAllRenderer(), risk=RiskLevel.HIGH)
        def deploy():
            pass

        with pytest.raises(AttestaDenied) as exc_info:
            deploy()

        assert exc_info.value.result.risk_assessment.level is RiskLevel.HIGH

    def test_risk_hints_passed_through(self):
        """risk_hints={...} should be reflected in the evaluation."""
        audit = RecordingAuditLogger()

        @gate(
            renderer=ApproveAllRenderer(),
            audit_logger=audit,
            risk_hints={"production": True, "cost_dollars": 50000},
        )
        def deploy(service: str):
            return f"deployed {service}"

        result = deploy("web")
        assert result == "deployed web"
        assert len(audit.entries) == 1

    def test_args_and_kwargs_forwarded(self):
        """All positional and keyword arguments are forwarded to the function."""

        @gate(renderer=ApproveAllRenderer())
        def fn(a, b, c=10):
            return a + b + c

        assert fn(1, 2, c=3) == 6

    def test_return_value_preserved(self):

        @gate(renderer=ApproveAllRenderer())
        def identity(x):
            return x

        assert identity(42) == 42
        assert identity("hello") == "hello"
        assert identity(None) is None


# =========================================================================
# @gate decorator -- async functions
# =========================================================================

class TestAttestaDecoratorAsync:
    async def test_async_bare_decorator(self):
        """@gate on an async function works."""

        @gate
        async def fetch(url: str) -> str:
            return f"fetched {url}"

        result = await fetch("https://example.com")
        assert result == "fetched https://example.com"

    async def test_async_with_options(self):

        @gate(renderer=ApproveAllRenderer())
        async def deploy(service: str) -> str:
            return f"deployed {service}"

        result = await deploy("api")
        assert result == "deployed api"

    async def test_async_preserves_name(self):

        @gate
        async def my_async_func():
            pass

        assert my_async_func.__name__ == "my_async_func"

    async def test_async_denied_raises(self):

        @gate(renderer=DenyAllRenderer(), risk="high")
        async def dangerous():
            return "nope"

        with pytest.raises(AttestaDenied) as exc_info:
            await dangerous()

        assert exc_info.value.result is not None
        assert exc_info.value.result.verdict is Verdict.DENIED

    async def test_async_denied_exception_carries_result(self):

        @gate(renderer=DenyAllRenderer(), risk="critical")
        async def nuke():
            pass

        with pytest.raises(AttestaDenied) as exc_info:
            await nuke()

        result = exc_info.value.result
        assert isinstance(result, ApprovalResult)
        assert result.risk_assessment.level is RiskLevel.CRITICAL
        assert result.verdict is Verdict.DENIED

    async def test_async_risk_hints(self):
        audit = RecordingAuditLogger()

        @gate(
            renderer=ApproveAllRenderer(),
            audit_logger=audit,
            risk_hints={"destructive": True},
        )
        async def purge(table: str) -> str:
            return f"purged {table}"

        result = await purge("sessions")
        assert result == "purged sessions"
        assert len(audit.entries) == 1

    async def test_async_return_value_preserved(self):

        @gate(renderer=ApproveAllRenderer())
        async def compute(x: int, y: int) -> int:
            return x * y

        assert await compute(6, 7) == 42

    async def test_async_gate_instance_attached(self):

        @gate
        async def func():
            pass

        assert hasattr(func, "__gate__")
        assert isinstance(func.__gate__, Attesta)


# =========================================================================
# @gate decorator -- metadata parameters
# =========================================================================

class TestAttestaDecoratorMetadata:
    async def test_agent_id_and_session_id(self):
        """agent_id and session_id are passed through to the context."""
        audit = RecordingAuditLogger()

        @gate(
            renderer=ApproveAllRenderer(),
            audit_logger=audit,
            agent_id="agent-007",
            session_id="sess-123",
        )
        async def action():
            return "done"

        await action()
        ctx, _ = audit.entries[0]
        assert ctx.agent_id == "agent-007"
        assert ctx.session_id == "sess-123"

    async def test_environment_parameter(self):
        audit = RecordingAuditLogger()

        @gate(
            renderer=ApproveAllRenderer(),
            audit_logger=audit,
            environment="production",
        )
        async def deploy():
            return "deployed"

        await deploy()
        ctx, _ = audit.entries[0]
        assert ctx.environment == "production"

    async def test_metadata_parameter(self):
        audit = RecordingAuditLogger()

        @gate(
            renderer=ApproveAllRenderer(),
            audit_logger=audit,
            metadata={"team": "platform", "ticket": "PLAT-42"},
        )
        async def update_config():
            return "updated"

        await update_config()
        ctx, _ = audit.entries[0]
        assert ctx.metadata["team"] == "platform"
        assert ctx.metadata["ticket"] == "PLAT-42"


# =========================================================================
# Attesta default challenge map
# =========================================================================

class TestDefaultChallengeMap:
    """Verify the default risk level to challenge type mapping."""

    async def test_low_risk_auto_approve(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.LOW)
        result = await g.evaluate(ActionContext(function_name="f"))
        # AUTO_APPROVE means no challenge result
        assert result.challenge_result is None

    async def test_medium_risk_confirm(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.MEDIUM)
        result = await g.evaluate(ActionContext(function_name="f"))
        assert result.challenge_result is not None
        assert result.challenge_result.challenge_type is ChallengeType.CONFIRM

    async def test_high_risk_quiz(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.HIGH)
        result = await g.evaluate(ActionContext(function_name="f"))
        assert result.challenge_result is not None
        assert result.challenge_result.challenge_type is ChallengeType.QUIZ

    async def test_critical_risk_multi_party(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.CRITICAL)
        result = await g.evaluate(ActionContext(function_name="f"))
        assert result.challenge_result is not None
        assert result.challenge_result.challenge_type is ChallengeType.MULTI_PARTY


# =========================================================================
# Attesta._assess_risk() -- risk override representative scores
# =========================================================================

class TestAssessRiskOverride:
    async def test_low_override_score(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.LOW)
        result = await g.evaluate(ActionContext(function_name="f"))
        assert result.risk_assessment.score == 0.15

    async def test_medium_override_score(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.MEDIUM)
        result = await g.evaluate(ActionContext(function_name="f"))
        assert result.risk_assessment.score == 0.45

    async def test_high_override_score(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.HIGH)
        result = await g.evaluate(ActionContext(function_name="f"))
        assert result.risk_assessment.score == 0.70

    async def test_critical_override_score(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.CRITICAL)
        result = await g.evaluate(ActionContext(function_name="f"))
        assert result.risk_assessment.score == 0.90

    async def test_override_has_manual_override_factor(self):
        g = Attesta(renderer=ApproveAllRenderer(), risk_override=RiskLevel.HIGH)
        result = await g.evaluate(ActionContext(function_name="f"))
        factor_names = [f.name for f in result.risk_assessment.factors]
        assert "manual_override" in factor_names
