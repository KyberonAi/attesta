"""Tests for attesta.core.risk -- risk scoring engine."""

from __future__ import annotations

import pytest

from attesta.core.risk import (
    CompositeRiskScorer,
    DefaultRiskScorer,
    FixedRiskScorer,
    MaxRiskScorer,
)
from attesta.core.types import (
    ActionContext,
    RiskAssessment,
    RiskLevel,
)

# =========================================================================
# Helpers
# =========================================================================

def _ctx(
    name: str = "my_func",
    args: tuple = (),
    kwargs: dict | None = None,
    doc: str | None = None,
    hints: dict | None = None,
    environment: str = "development",
) -> ActionContext:
    """Shortcut to build a minimal ActionContext for testing."""
    return ActionContext(
        function_name=name,
        args=args,
        kwargs=kwargs or {},
        function_doc=doc,
        hints=hints or {},
        environment=environment,
    )


# =========================================================================
# DefaultRiskScorer -- function name analysis
# =========================================================================

class TestDefaultRiskScorerFunctionName:
    """Verify that destructive, mutating, and read verbs are scored correctly."""

    def _score_name(self, name: str) -> float:
        """Score a function by name only (fresh scorer each time to reset novelty)."""
        scorer = DefaultRiskScorer()
        return scorer.score(_ctx(name=name))

    def test_destructive_delete_scores_high(self):
        score = self._score_name("delete_user")
        # destructive verb contributes 0.95 * 0.30 = 0.285 from name alone
        assert score > 0.25

    def test_destructive_drop_table_scores_high(self):
        score = self._score_name("drop_table")
        assert score > 0.25

    def test_destructive_destroy_scores_high(self):
        score = self._score_name("destroy_resource")
        assert score > 0.25

    def test_destructive_purge_scores_high(self):
        score = self._score_name("purge_cache")
        assert score > 0.25

    def test_destructive_truncate_scores_high(self):
        score = self._score_name("truncate_logs")
        assert score > 0.25

    def test_destructive_remove_scores_high(self):
        score = self._score_name("remove_item")
        assert score > 0.25

    def test_destructive_kill_scores_high(self):
        score = self._score_name("kill_process")
        assert score > 0.25

    def test_mutating_deploy_scores_moderate(self):
        score = self._score_name("deploy_service")
        # mutating verb contributes 0.55 * 0.30 = 0.165 from name alone
        assert score > 0.1

    def test_read_get_scores_low(self):
        score = self._score_name("get_user")
        # read verb contributes 0.1 * 0.30 = 0.03 from name alone
        assert score < 0.4

    def test_read_list_scores_low(self):
        score = self._score_name("list_items")
        assert score < 0.4

    def test_read_fetch_scores_low(self):
        score = self._score_name("fetch_data")
        assert score < 0.4

    def test_read_search_scores_low(self):
        score = self._score_name("search_records")
        assert score < 0.4

    def test_camel_case_destructive(self):
        """camelCase function names should be correctly tokenised."""
        score = self._score_name("deleteAllUsers")
        assert score > 0.25

    def test_destructive_higher_than_read(self):
        scorer = DefaultRiskScorer()
        delete_score = scorer.score(_ctx(name="delete_everything"))
        scorer.reset_novelty()
        read_score = scorer.score(_ctx(name="read_config"))
        assert delete_score > read_score


# =========================================================================
# DefaultRiskScorer -- argument analysis
# =========================================================================

class TestDefaultRiskScorerArguments:
    """Verify that sensitive argument patterns are detected."""

    def _score_args(self, args: tuple = (), kwargs: dict | None = None) -> float:
        scorer = DefaultRiskScorer()
        return scorer.score(_ctx(name="do_something", args=args, kwargs=kwargs))

    def test_prod_path_scores_high(self):
        score = self._score_args(args=("/etc/production/config.yaml",))
        # "production" matches _SENSITIVE_PATTERNS -> 0.9 * 0.25 from args
        assert score > 0.15

    def test_sql_drop_scores_high(self):
        score = self._score_args(args=("DROP TABLE users;",))
        assert score > 0.15

    def test_sql_delete_scores_high(self):
        score = self._score_args(args=("DELETE FROM sessions WHERE 1=1;",))
        assert score > 0.15

    def test_sql_truncate_scores_high(self):
        score = self._score_args(args=("TRUNCATE TABLE logs;",))
        assert score > 0.15

    def test_shell_rm_rf_scores_high(self):
        score = self._score_args(args=("rm -rf /",))
        assert score > 0.15

    def test_shell_sudo_scores_high(self):
        score = self._score_args(args=("sudo reboot",))
        assert score > 0.15

    def test_secret_in_kwarg_scores_high(self):
        score = self._score_args(kwargs={"config": "secret_key=abc123"})
        assert score > 0.15

    def test_password_detected(self):
        score = self._score_args(kwargs={"credential": "password=hunter2"})
        assert score > 0.15

    def test_benign_args_score_low(self):
        score = self._score_args(args=("hello", "world"))
        # benign args contribute 0.05 * 0.25 = 0.0125
        assert score < 0.5

    def test_url_in_args_medium_risk(self):
        score = self._score_args(args=("https://example.com/api",))
        # network pattern -> 0.5 * 0.25 = 0.125
        assert score > 0.05

    def test_no_args_scores_lowest(self):
        score = self._score_args()
        # no arguments -> 0.0 * 0.25 = 0 from this factor
        assert score < 0.5


# =========================================================================
# DefaultRiskScorer -- docstring analysis
# =========================================================================

class TestDefaultRiskScorerDocstring:
    """Verify that docstring keywords influence the score."""

    def _score_doc(self, doc: str | None) -> float:
        scorer = DefaultRiskScorer()
        return scorer.score(_ctx(name="neutral_func", doc=doc))

    def test_irreversible_keyword(self):
        score = self._score_doc("This action is irreversible and will delete data.")
        assert score > 0.15

    def test_destructive_keyword(self):
        score = self._score_doc("This is a destructive operation.")
        assert score > 0.15

    def test_dangerous_keyword(self):
        score = self._score_doc("Warning: dangerous when used in production.")
        assert score > 0.15

    def test_caution_keyword(self):
        score = self._score_doc("Use caution when calling this function.")
        assert score > 0.05

    def test_no_docstring(self):
        score = self._score_doc(None)
        # "no docstring" -> 0.1 * 0.20 = 0.02
        assert score < 0.5

    def test_safe_docstring(self):
        score = self._score_doc("Returns the current time as a string.")
        assert score < 0.5


# =========================================================================
# DefaultRiskScorer -- hints analysis
# =========================================================================

class TestDefaultRiskScorerHints:
    """Verify that caller-supplied hints influence the score."""

    def _score_hints(self, hints: dict) -> float:
        scorer = DefaultRiskScorer()
        return scorer.score(_ctx(name="neutral_func", hints=hints))

    def test_production_hint_true(self):
        score = self._score_hints({"production": True})
        # bool True -> 0.3 contribution -> 0.3 * 0.15 = 0.045 from hints
        assert score > 0.0

    def test_destructive_hint_true(self):
        score = self._score_hints({"destructive": True})
        assert score > 0.0

    def test_pii_hint_true(self):
        score = self._score_hints({"pii": True})
        assert score > 0.0

    def test_multiple_boolean_hints(self):
        low = self._score_hints({"production": True})
        high = self._score_hints({"production": True, "destructive": True, "pii": True})
        assert high > low

    def test_numeric_hint_large_value(self):
        score = self._score_hints({"cost_dollars": 50_000})
        # 50000/10000 = 5.0, capped to 1.0, * 0.8 = 0.8
        assert score > 0.0

    def test_empty_hints(self):
        score = self._score_hints({})
        # no hints -> 0.0 * 0.15 = 0 from this factor
        assert score < 0.5


# =========================================================================
# DefaultRiskScorer -- novelty
# =========================================================================

class TestDefaultRiskScorerNovelty:
    """Verify that first calls are scored as more novel (risky)."""

    def test_first_call_higher_novelty(self):
        scorer = DefaultRiskScorer()
        ctx = _ctx(name="novel_func")
        first = scorer.score(ctx)
        second = scorer.score(ctx)
        # First call has novelty=0.9, second has novelty=0.82
        # So first total should be higher than second.
        assert first > second

    def test_novelty_decreases_over_calls(self):
        scorer = DefaultRiskScorer()
        scores = []
        for _ in range(12):
            scores.append(scorer.score(_ctx(name="repeated_func")))
        # Novelty factor decreases, so the total should trend downward
        assert scores[0] > scores[-1]

    def test_reset_novelty(self):
        scorer = DefaultRiskScorer()
        scorer.score(_ctx(name="func_a"))
        scorer.score(_ctx(name="func_a"))
        scorer.reset_novelty()
        # After reset, should behave like first call again
        first_after_reset = scorer.score(_ctx(name="func_a"))
        scorer.reset_novelty()
        fresh_first = scorer.score(_ctx(name="func_a"))
        assert abs(first_after_reset - fresh_first) < 0.01


# =========================================================================
# DefaultRiskScorer -- assess() method
# =========================================================================

class TestDefaultRiskScorerAssess:
    """Verify the assess() convenience wrapper."""

    def test_returns_risk_assessment(self):
        scorer = DefaultRiskScorer()
        result = scorer.assess(_ctx(name="delete_all"))
        assert isinstance(result, RiskAssessment)
        assert result.scorer_name == "default"
        assert 0.0 <= result.score <= 1.0
        assert isinstance(result.level, RiskLevel)

    def test_factors_populated(self):
        scorer = DefaultRiskScorer()
        result = scorer.assess(_ctx(name="delete_all"))
        factor_names = {f.name for f in result.factors}
        assert "function_name" in factor_names
        assert "arguments" in factor_names
        assert "docstring" in factor_names
        assert "hints" in factor_names
        assert "novelty" in factor_names

    def test_assess_score_matches_score_method(self):
        scorer = DefaultRiskScorer()
        ctx = _ctx(name="deploy_prod")
        raw = scorer.score(ctx)
        scorer.reset_novelty()
        assessment = scorer.assess(ctx)
        assert abs(assessment.score - raw) < 0.01


# =========================================================================
# FixedRiskScorer
# =========================================================================

class TestFixedRiskScorer:
    def test_returns_fixed_value(self):
        scorer = FixedRiskScorer(0.42)
        ctx = _ctx(name="anything")
        assert scorer.score(ctx) == 0.42

    def test_name_includes_value(self):
        scorer = FixedRiskScorer(0.42)
        assert "0.42" in scorer.name

    def test_default_is_0_5(self):
        scorer = FixedRiskScorer()
        assert scorer.score(_ctx()) == 0.5

    def test_boundary_zero(self):
        scorer = FixedRiskScorer(0.0)
        assert scorer.score(_ctx()) == 0.0

    def test_boundary_one(self):
        scorer = FixedRiskScorer(1.0)
        assert scorer.score(_ctx()) == 1.0

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="fixed_score must be in"):
            FixedRiskScorer(-0.1)

    def test_above_one_raises(self):
        with pytest.raises(ValueError, match="fixed_score must be in"):
            FixedRiskScorer(1.1)

    def test_assess_returns_assessment(self):
        scorer = FixedRiskScorer(0.9)
        result = scorer.assess(_ctx())
        assert isinstance(result, RiskAssessment)
        assert result.score == 0.9
        assert result.level is RiskLevel.CRITICAL
        assert len(result.factors) == 1
        assert result.factors[0].name == "fixed"

    def test_assess_low_score_level(self):
        scorer = FixedRiskScorer(0.1)
        result = scorer.assess(_ctx())
        assert result.level is RiskLevel.LOW

    def test_ignores_context(self):
        scorer = FixedRiskScorer(0.33)
        dangerous = _ctx(name="delete_everything", args=("DROP TABLE users;",))
        safe = _ctx(name="get_time")
        assert scorer.score(dangerous) == scorer.score(safe)


# =========================================================================
# CompositeRiskScorer
# =========================================================================

class TestCompositeRiskScorer:
    def test_weighted_average(self):
        # Two fixed scorers with equal weight should average to 0.5
        s1 = FixedRiskScorer(0.2)
        s2 = FixedRiskScorer(0.8)
        composite = CompositeRiskScorer(scorers=[(s1, 1.0), (s2, 1.0)])
        result = composite.score(_ctx())
        assert abs(result - 0.5) < 0.01

    def test_weighted_average_unequal_weights(self):
        s1 = FixedRiskScorer(0.0)
        s2 = FixedRiskScorer(1.0)
        composite = CompositeRiskScorer(scorers=[(s1, 3.0), (s2, 1.0)])
        # Expected: (0*3 + 1*1) / 4 = 0.25
        result = composite.score(_ctx())
        assert abs(result - 0.25) < 0.01

    def test_name_includes_children(self):
        s1 = FixedRiskScorer(0.1)
        s2 = FixedRiskScorer(0.9)
        composite = CompositeRiskScorer(scorers=[(s1, 1.0), (s2, 1.0)])
        assert "composite(" in composite.name
        assert "fixed(" in composite.name

    def test_empty_scorers_raises(self):
        with pytest.raises(ValueError, match="at least one scorer"):
            CompositeRiskScorer(scorers=[])

    def test_zero_total_weight_raises(self):
        s1 = FixedRiskScorer(0.5)
        with pytest.raises(ValueError, match="Total weight must be positive"):
            CompositeRiskScorer(scorers=[(s1, 0.0)])

    def test_assess_returns_factor_per_scorer(self):
        s1 = FixedRiskScorer(0.3)
        s2 = FixedRiskScorer(0.7)
        composite = CompositeRiskScorer(scorers=[(s1, 1.0), (s2, 1.0)])
        result = composite.assess(_ctx())
        assert isinstance(result, RiskAssessment)
        assert len(result.factors) == 2

    def test_single_scorer_passthrough(self):
        s = FixedRiskScorer(0.6)
        composite = CompositeRiskScorer(scorers=[(s, 1.0)])
        assert abs(composite.score(_ctx()) - 0.6) < 0.01

    def test_combines_default_and_fixed(self):
        default = DefaultRiskScorer()
        fixed = FixedRiskScorer(0.0)
        composite = CompositeRiskScorer(scorers=[(default, 0.5), (fixed, 0.5)])
        ctx = _ctx(name="delete_all")
        composite_score = composite.score(ctx)
        # Should be lower than pure default because fixed pulls toward 0
        default.reset_novelty()
        pure_default = default.score(ctx)
        assert composite_score < pure_default


# =========================================================================
# MaxRiskScorer
# =========================================================================

class TestMaxRiskScorer:
    def test_takes_maximum(self):
        s1 = FixedRiskScorer(0.2)
        s2 = FixedRiskScorer(0.8)
        s3 = FixedRiskScorer(0.5)
        mx = MaxRiskScorer(scorers=[s1, s2, s3])
        assert abs(mx.score(_ctx()) - 0.8) < 0.01

    def test_name_format(self):
        s1 = FixedRiskScorer(0.1)
        s2 = FixedRiskScorer(0.9)
        mx = MaxRiskScorer(scorers=[s1, s2])
        assert "max(" in mx.name

    def test_empty_scorers_raises(self):
        with pytest.raises(ValueError, match="at least one scorer"):
            MaxRiskScorer(scorers=[])

    def test_single_scorer(self):
        s = FixedRiskScorer(0.4)
        mx = MaxRiskScorer(scorers=[s])
        assert abs(mx.score(_ctx()) - 0.4) < 0.01

    def test_assess_returns_factors(self):
        s1 = FixedRiskScorer(0.3)
        s2 = FixedRiskScorer(0.7)
        mx = MaxRiskScorer(scorers=[s1, s2])
        result = mx.assess(_ctx())
        assert isinstance(result, RiskAssessment)
        assert len(result.factors) == 2
        assert result.score == pytest.approx(0.7, abs=0.01)

    def test_max_is_conservative(self):
        """MaxRiskScorer should always be >= CompositeRiskScorer."""
        s1 = FixedRiskScorer(0.1)
        s2 = FixedRiskScorer(0.9)
        mx = MaxRiskScorer(scorers=[s1, s2])
        composite = CompositeRiskScorer(scorers=[(s1, 1.0), (s2, 1.0)])
        ctx = _ctx()
        assert mx.score(ctx) >= composite.score(ctx)


# =========================================================================
# Score clamping
# =========================================================================

class TestScoreClamping:
    """Ensure scores are always clamped to [0.0, 1.0]."""

    def test_default_scorer_never_exceeds_one(self):
        scorer = DefaultRiskScorer()
        # Stack every risk signal simultaneously
        ctx = _ctx(
            name="delete_all_production_data",
            args=("DROP TABLE users; rm -rf / sudo reboot",),
            kwargs={"path": "/etc/production/secret.env"},
            doc="DANGEROUS: This is an irreversible destructive critical operation.",
            hints={"production": True, "destructive": True, "pii": True, "cost_dollars": 99999},
            environment="production",
        )
        score = scorer.score(ctx)
        assert 0.0 <= score <= 1.0

    def test_default_scorer_never_below_zero(self):
        scorer = DefaultRiskScorer()
        ctx = _ctx(name="get_time")
        score = scorer.score(ctx)
        assert 0.0 <= score <= 1.0
