"""Tests for attesta.core.types -- enums, dataclasses, and protocols."""

from __future__ import annotations

from datetime import datetime

import pytest

from attesta.core.types import (
    ActionContext,
    ApprovalResult,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    Verdict,
)

# =========================================================================
# RiskLevel.from_score()
# =========================================================================


class TestRiskLevelFromScore:
    """Boundary-condition tests for the score -> level mapping.

    Ranges:
        LOW      [0.0, 0.3)
        MEDIUM   [0.3, 0.6)
        HIGH     [0.6, 0.8)
        CRITICAL [0.8, 1.0]
    """

    # -- exact boundaries --------------------------------------------------

    def test_zero_is_low(self):
        assert RiskLevel.from_score(0.0) is RiskLevel.LOW

    def test_just_below_0_3_is_low(self):
        assert RiskLevel.from_score(0.29) is RiskLevel.LOW

    def test_0_3_is_medium(self):
        assert RiskLevel.from_score(0.3) is RiskLevel.MEDIUM

    def test_just_below_0_6_is_medium(self):
        assert RiskLevel.from_score(0.59) is RiskLevel.MEDIUM

    def test_0_6_is_high(self):
        assert RiskLevel.from_score(0.6) is RiskLevel.HIGH

    def test_just_below_0_8_is_high(self):
        assert RiskLevel.from_score(0.79) is RiskLevel.HIGH

    def test_0_8_is_critical(self):
        assert RiskLevel.from_score(0.8) is RiskLevel.CRITICAL

    def test_1_0_is_critical(self):
        assert RiskLevel.from_score(1.0) is RiskLevel.CRITICAL

    # -- mid-range representative values -----------------------------------

    def test_low_midpoint(self):
        assert RiskLevel.from_score(0.15) is RiskLevel.LOW

    def test_medium_midpoint(self):
        assert RiskLevel.from_score(0.45) is RiskLevel.MEDIUM

    def test_high_midpoint(self):
        assert RiskLevel.from_score(0.70) is RiskLevel.HIGH

    def test_critical_midpoint(self):
        assert RiskLevel.from_score(0.90) is RiskLevel.CRITICAL

    # -- out-of-range values -----------------------------------------------

    def test_negative_raises(self):
        with pytest.raises(ValueError, match=r"Risk score must be in \[0, 1\]"):
            RiskLevel.from_score(-0.01)

    def test_above_one_raises(self):
        with pytest.raises(ValueError, match=r"Risk score must be in \[0, 1\]"):
            RiskLevel.from_score(1.01)

    def test_large_negative_raises(self):
        with pytest.raises(ValueError):
            RiskLevel.from_score(-100.0)

    def test_large_positive_raises(self):
        with pytest.raises(ValueError):
            RiskLevel.from_score(100.0)


# =========================================================================
# RiskLevel enum values
# =========================================================================


class TestRiskLevelEnum:
    def test_values(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_construct_from_value(self):
        assert RiskLevel("low") is RiskLevel.LOW
        assert RiskLevel("critical") is RiskLevel.CRITICAL

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            RiskLevel("unknown")


# =========================================================================
# Verdict enum
# =========================================================================


class TestVerdictEnum:
    def test_all_values(self):
        assert Verdict.APPROVED.value == "approved"
        assert Verdict.DENIED.value == "denied"
        assert Verdict.MODIFIED.value == "modified"
        assert Verdict.TIMED_OUT.value == "timed_out"
        assert Verdict.ESCALATED.value == "escalated"

    def test_member_count(self):
        assert len(Verdict) == 5


# =========================================================================
# ChallengeType enum
# =========================================================================


class TestChallengeTypeEnum:
    def test_all_values(self):
        assert ChallengeType.AUTO_APPROVE.value == "auto_approve"
        assert ChallengeType.CONFIRM.value == "confirm"
        assert ChallengeType.QUIZ.value == "quiz"
        assert ChallengeType.TEACH_BACK.value == "teach_back"
        assert ChallengeType.MULTI_PARTY.value == "multi_party"

    def test_member_count(self):
        assert len(ChallengeType) == 5


# =========================================================================
# ActionContext
# =========================================================================


class TestActionContext:
    """Tests for ActionContext defaults and .description property."""

    def test_defaults(self):
        ctx = ActionContext(function_name="foo")
        assert ctx.function_name == "foo"
        assert ctx.args == ()
        assert ctx.kwargs == {}
        assert ctx.function_doc is None
        assert ctx.hints == {}
        assert ctx.agent_id is None
        assert ctx.session_id is None
        assert ctx.environment == "development"
        assert isinstance(ctx.timestamp, datetime)
        assert ctx.source_code is None
        assert ctx.metadata == {}

    def test_description_no_args(self):
        ctx = ActionContext(function_name="do_thing")
        assert ctx.description == "do_thing()"

    def test_description_positional_args(self):
        ctx = ActionContext(function_name="deploy", args=("web", "v1.2"))
        assert ctx.description == "deploy('web', 'v1.2')"

    def test_description_kwargs_only(self):
        ctx = ActionContext(
            function_name="deploy",
            kwargs={"service": "web", "version": "v1.2"},
        )
        assert ctx.description == "deploy(service='web', version='v1.2')"

    def test_description_mixed_args_and_kwargs(self):
        ctx = ActionContext(
            function_name="copy",
            args=("/src",),
            kwargs={"dest": "/dst"},
        )
        assert ctx.description == "copy('/src', dest='/dst')"

    def test_custom_environment(self):
        ctx = ActionContext(function_name="f", environment="production")
        assert ctx.environment == "production"

    def test_hints_are_independent_instances(self):
        """Ensure default_factory creates a new dict each time."""
        a = ActionContext(function_name="a")
        b = ActionContext(function_name="b")
        a.hints["x"] = 1
        assert "x" not in b.hints


# =========================================================================
# RiskFactor
# =========================================================================


class TestRiskFactor:
    def test_defaults(self):
        f = RiskFactor(name="test", contribution=0.3, description="desc")
        assert f.name == "test"
        assert f.contribution == 0.3
        assert f.description == "desc"
        assert f.evidence is None

    def test_with_evidence(self):
        f = RiskFactor(
            name="test",
            contribution=0.5,
            description="desc",
            evidence="saw DROP TABLE",
        )
        assert f.evidence == "saw DROP TABLE"


# =========================================================================
# RiskAssessment
# =========================================================================


class TestRiskAssessment:
    def test_valid_assessment(self):
        ra = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)
        assert ra.score == 0.5
        assert ra.level is RiskLevel.MEDIUM
        assert ra.factors == []
        assert ra.scorer_name == "default"

    def test_with_factors(self):
        factors = [
            RiskFactor(name="f1", contribution=0.3, description="d1"),
            RiskFactor(name="f2", contribution=0.2, description="d2"),
        ]
        ra = RiskAssessment(
            score=0.5,
            level=RiskLevel.MEDIUM,
            factors=factors,
            scorer_name="custom",
        )
        assert len(ra.factors) == 2
        assert ra.scorer_name == "custom"

    def test_score_below_zero_raises(self):
        with pytest.raises(ValueError, match=r"Risk score must be in \[0, 1\]"):
            RiskAssessment(score=-0.1, level=RiskLevel.LOW)

    def test_score_above_one_raises(self):
        with pytest.raises(ValueError, match=r"Risk score must be in \[0, 1\]"):
            RiskAssessment(score=1.1, level=RiskLevel.HIGH)

    def test_boundary_zero_valid(self):
        ra = RiskAssessment(score=0.0, level=RiskLevel.LOW)
        assert ra.score == 0.0

    def test_boundary_one_valid(self):
        ra = RiskAssessment(score=1.0, level=RiskLevel.CRITICAL)
        assert ra.score == 1.0


# =========================================================================
# ChallengeResult
# =========================================================================


class TestChallengeResult:
    def test_defaults(self):
        cr = ChallengeResult(passed=True, challenge_type=ChallengeType.CONFIRM)
        assert cr.passed is True
        assert cr.challenge_type is ChallengeType.CONFIRM
        assert cr.responder == "default"
        assert cr.response_time_seconds == 0.0
        assert cr.questions_asked == 0
        assert cr.questions_correct == 0
        assert cr.details == {}

    def test_quiz_result(self):
        cr = ChallengeResult(
            passed=False,
            challenge_type=ChallengeType.QUIZ,
            responder="operator@example.com",
            response_time_seconds=12.5,
            questions_asked=3,
            questions_correct=1,
        )
        assert cr.passed is False
        assert cr.questions_asked == 3
        assert cr.questions_correct == 1


# =========================================================================
# ApprovalResult
# =========================================================================


class TestApprovalResult:
    def test_defaults(self):
        ra = RiskAssessment(score=0.1, level=RiskLevel.LOW)
        ar = ApprovalResult(verdict=Verdict.APPROVED, risk_assessment=ra)
        assert ar.verdict is Verdict.APPROVED
        assert ar.challenge_result is None
        assert ar.approvers == []
        assert ar.review_time_seconds == 0.0
        assert ar.audit_entry_id is None
        assert isinstance(ar.timestamp, datetime)
        assert ar.modification is None

    def test_denied_with_challenge(self):
        ra = RiskAssessment(score=0.7, level=RiskLevel.HIGH)
        cr = ChallengeResult(passed=False, challenge_type=ChallengeType.QUIZ)
        ar = ApprovalResult(
            verdict=Verdict.DENIED,
            risk_assessment=ra,
            challenge_result=cr,
            review_time_seconds=15.0,
        )
        assert ar.verdict is Verdict.DENIED
        assert ar.challenge_result is not None
        assert ar.challenge_result.passed is False

    def test_modified_with_modification_text(self):
        ra = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)
        ar = ApprovalResult(
            verdict=Verdict.MODIFIED,
            risk_assessment=ra,
            modification="Changed target from prod to staging",
        )
        assert ar.modification == "Changed target from prod to staging"
