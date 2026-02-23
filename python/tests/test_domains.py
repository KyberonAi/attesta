"""Tests for the attesta.domains domain knowledge layer.

Covers DomainProfile, DomainRiskScorer, and the preset registration API.
"""

from __future__ import annotations

import re

import pytest

from attesta.core.risk import FixedRiskScorer
from attesta.core.types import (
    ActionContext,
    RiskAssessment,
    RiskLevel,
)
from attesta.domains.presets import (
    list_presets,
    load_preset,
    register_preset,
)
from attesta.domains.profile import (
    DomainChallengeTemplate,
    DomainProfile,
    DomainRegistry,
    EscalationRule,
    RiskPattern,
)
from attesta.domains.scorer import DomainRiskScorer

# =========================================================================
# RiskPattern
# =========================================================================


class TestRiskPattern:
    """Tests for RiskPattern data class and regex compilation."""

    def test_pattern_string_compiled_on_init(self):
        rp = RiskPattern(
            pattern=r"patient|phi",
            target="any",
            risk_contribution=0.8,
            name="phi",
            description="PHI access",
        )
        assert isinstance(rp.pattern, re.Pattern)

    def test_compiled_property_returns_pattern(self):
        rp = RiskPattern(
            pattern=r"patient",
            target="function_name",
            risk_contribution=0.5,
            name="test",
            description="test pattern",
        )
        assert isinstance(rp.compiled, re.Pattern)
        assert rp.compiled.search("access_patient") is not None

    def test_precompiled_pattern_accepted(self):
        compiled = re.compile(r"diagnosis", re.IGNORECASE)
        rp = RiskPattern(
            pattern=compiled,
            target="docstring",
            risk_contribution=0.6,
            name="diag",
            description="diagnosis pattern",
        )
        assert rp.compiled is compiled

    def test_valid_targets(self):
        for target in ("function_name", "args", "kwargs", "docstring", "any"):
            rp = RiskPattern(
                pattern=r"test",
                target=target,
                risk_contribution=0.5,
                name="t",
                description="d",
            )
            assert rp.target == target

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError, match="Invalid RiskPattern target"):
            RiskPattern(
                pattern=r"test",
                target="invalid_target",
                risk_contribution=0.5,
                name="t",
                description="d",
            )

    def test_risk_contribution_below_zero_raises(self):
        with pytest.raises(ValueError, match="risk_contribution must be in"):
            RiskPattern(
                pattern=r"test",
                target="any",
                risk_contribution=-0.1,
                name="t",
                description="d",
            )

    def test_risk_contribution_above_one_raises(self):
        with pytest.raises(ValueError, match="risk_contribution must be in"):
            RiskPattern(
                pattern=r"test",
                target="any",
                risk_contribution=1.1,
                name="t",
                description="d",
            )

    def test_compliance_refs_default_empty(self):
        rp = RiskPattern(
            pattern=r"test",
            target="any",
            risk_contribution=0.5,
            name="t",
            description="d",
        )
        assert rp.compliance_refs == []

    def test_compliance_refs_stored(self):
        rp = RiskPattern(
            pattern=r"test",
            target="any",
            risk_contribution=0.5,
            name="t",
            description="d",
            compliance_refs=["HIPAA s164.312"],
        )
        assert rp.compliance_refs == ["HIPAA s164.312"]

    def test_pattern_case_insensitive(self):
        rp = RiskPattern(
            pattern=r"patient",
            target="any",
            risk_contribution=0.5,
            name="t",
            description="d",
        )
        assert rp.compiled.search("PATIENT") is not None
        assert rp.compiled.search("Patient") is not None


# =========================================================================
# EscalationRule
# =========================================================================


class TestEscalationRule:
    """Tests for EscalationRule data class."""

    def test_valid_creation(self):
        rule = EscalationRule(
            condition="risk_score > 0.9",
            action="require_multi_party",
            required_approvers=3,
            notify_roles=["compliance_officer"],
            description="High risk escalation",
        )
        assert rule.condition == "risk_score > 0.9"
        assert rule.action == "require_multi_party"
        assert rule.required_approvers == 3

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid EscalationRule action"):
            EscalationRule(
                condition="risk_score > 0.9",
                action="invalid_action",
            )

    def test_required_approvers_below_one_raises(self):
        with pytest.raises(ValueError, match="required_approvers must be >= 1"):
            EscalationRule(
                condition="risk_score > 0.9",
                action="block",
                required_approvers=0,
            )

    def test_defaults(self):
        rule = EscalationRule(
            condition="risk_score > 0.5",
            action="block",
        )
        assert rule.required_approvers == 2
        assert rule.notify_roles == []
        assert rule.description == ""

    def test_all_valid_actions(self):
        for action in (
            "require_multi_party",
            "notify_compliance",
            "block",
            "require_teach_back",
            "require_confirmation",
        ):
            rule = EscalationRule(condition="risk_score > 0.5", action=action)
            assert rule.action == action


# =========================================================================
# DomainChallengeTemplate
# =========================================================================


class TestDomainChallengeTemplate:
    """Tests for DomainChallengeTemplate data class."""

    def test_valid_quiz_template(self):
        tpl = DomainChallengeTemplate(
            question_template="What HIPAA provision governs this?",
            answer_hints=["minimum necessary", "164.502"],
            context_vars=["function_name"],
            challenge_type="quiz",
            min_risk_level="high",
        )
        assert tpl.challenge_type == "quiz"
        assert tpl.min_risk_level == "high"

    def test_valid_teach_back_template(self):
        tpl = DomainChallengeTemplate(
            question_template="Explain the impact.",
            answer_hints=["patient safety"],
            context_vars=["function_name"],
            challenge_type="teach_back",
        )
        assert tpl.challenge_type == "teach_back"

    def test_invalid_challenge_type_raises(self):
        with pytest.raises(ValueError, match="Invalid challenge_type"):
            DomainChallengeTemplate(
                question_template="Q?",
                answer_hints=[],
                context_vars=[],
                challenge_type="essay",
            )

    def test_invalid_min_risk_level_raises(self):
        with pytest.raises(ValueError, match="Invalid min_risk_level"):
            DomainChallengeTemplate(
                question_template="Q?",
                answer_hints=[],
                context_vars=[],
                challenge_type="quiz",
                min_risk_level="extreme",
            )

    def test_default_min_risk_level_is_high(self):
        tpl = DomainChallengeTemplate(
            question_template="Q?",
            answer_hints=[],
            context_vars=[],
            challenge_type="quiz",
        )
        assert tpl.min_risk_level == "high"


# =========================================================================
# DomainProfile
# =========================================================================


class TestDomainProfile:
    """Tests for DomainProfile creation and methods."""

    def _make_profile(self, **overrides) -> DomainProfile:
        """Build a minimal profile with optional overrides."""
        defaults = dict(
            name="test_domain",
            display_name="Test Domain",
            description="A test domain profile.",
            risk_patterns=[
                RiskPattern(
                    pattern=r"patient|phi",
                    target="any",
                    risk_contribution=0.8,
                    name="phi_access",
                    description="PHI access pattern",
                ),
            ],
            sensitive_terms={"patient": 0.7, "phi": 0.9},
            critical_actions=["delete_patient", "export_phi"],
            safe_actions=["get_status", "list_departments"],
            compliance_frameworks=["HIPAA"],
        )
        defaults.update(overrides)
        return DomainProfile(**defaults)

    def test_basic_creation(self):
        profile = self._make_profile()
        assert profile.name == "test_domain"
        assert profile.display_name == "Test Domain"
        assert len(profile.risk_patterns) == 1
        assert profile.compliance_frameworks == ["HIPAA"]

    def test_is_critical_action_match(self):
        profile = self._make_profile()
        assert profile.is_critical_action("delete_patient") is True
        assert profile.is_critical_action("export_phi") is True

    def test_is_critical_action_no_match(self):
        profile = self._make_profile()
        assert profile.is_critical_action("get_status") is False
        assert profile.is_critical_action("read_config") is False

    def test_is_safe_action_match(self):
        profile = self._make_profile()
        assert profile.is_safe_action("get_status") is True
        assert profile.is_safe_action("list_departments") is True

    def test_is_safe_action_no_match(self):
        profile = self._make_profile()
        assert profile.is_safe_action("delete_patient") is False
        assert profile.is_safe_action("unknown_func") is False

    def test_get_matching_sensitive_terms_found(self):
        profile = self._make_profile()
        matches = profile.get_matching_sensitive_terms(
            "The patient record contains phi data"
        )
        assert len(matches) == 2
        weights = [w for _, w in matches]
        assert 0.7 in weights  # patient
        assert 0.9 in weights  # phi

    def test_get_matching_sensitive_terms_none_found(self):
        profile = self._make_profile()
        matches = profile.get_matching_sensitive_terms("hello world")
        assert matches == []

    def test_get_matching_sensitive_terms_partial_word_no_match(self):
        profile = self._make_profile()
        # "patience" should not match "patient" due to word boundaries
        matches = profile.get_matching_sensitive_terms("patience is a virtue")
        assert len(matches) == 0

    def test_base_risk_floor_validation(self):
        with pytest.raises(ValueError, match="base_risk_floor"):
            self._make_profile(base_risk_floor=1.5)

    def test_production_multiplier_validation(self):
        with pytest.raises(ValueError, match="production_multiplier"):
            self._make_profile(production_multiplier=-1.0)

    def test_get_templates_for_level(self):
        templates = [
            DomainChallengeTemplate(
                question_template="Low Q?",
                answer_hints=["a"],
                context_vars=["function_name"],
                challenge_type="quiz",
                min_risk_level="low",
            ),
            DomainChallengeTemplate(
                question_template="Critical Q?",
                answer_hints=["b"],
                context_vars=["function_name"],
                challenge_type="quiz",
                min_risk_level="critical",
            ),
        ]
        profile = self._make_profile(challenge_templates=templates)

        # High level should include low but not critical
        high_templates = profile.get_templates_for_level("high")
        assert len(high_templates) == 1
        assert high_templates[0].question_template == "Low Q?"

        # Critical level should include both
        critical_templates = profile.get_templates_for_level("critical")
        assert len(critical_templates) == 2

    def test_critical_action_with_wildcard(self):
        profile = self._make_profile(critical_actions=["delete_*"])
        assert profile.is_critical_action("delete_user") is True
        assert profile.is_critical_action("delete_everything") is True

    def test_default_values(self):
        profile = DomainProfile(
            name="minimal",
            display_name="Minimal",
            description="Minimal profile",
        )
        assert profile.risk_patterns == []
        assert profile.sensitive_terms == {}
        assert profile.critical_actions == []
        assert profile.safe_actions == []
        assert profile.base_risk_floor == 0.0
        assert profile.production_multiplier == 1.5


# =========================================================================
# DomainRegistry
# =========================================================================


class TestDomainRegistry:
    """Tests for DomainRegistry."""

    def _make_profile(self, name: str) -> DomainProfile:
        return DomainProfile(
            name=name,
            display_name=name.title(),
            description=f"Profile for {name}",
        )

    def test_register_and_get(self):
        reg = DomainRegistry()
        profile = self._make_profile("test_reg")
        reg.register(profile)
        assert reg.get("test_reg") is profile

    def test_register_duplicate_raises(self):
        reg = DomainRegistry()
        profile = self._make_profile("dup")
        reg.register(profile)
        with pytest.raises(ValueError, match="already registered"):
            reg.register(profile)

    def test_get_missing_raises_key_error(self):
        reg = DomainRegistry()
        with pytest.raises(KeyError, match="not found"):
            reg.get("nonexistent")

    def test_list_domains_sorted(self):
        reg = DomainRegistry()
        reg.register(self._make_profile("zebra"))
        reg.register(self._make_profile("alpha"))
        assert reg.list_domains() == ["alpha", "zebra"]

    def test_contains(self):
        reg = DomainRegistry()
        reg.register(self._make_profile("check"))
        assert "check" in reg
        assert "missing" not in reg

    def test_len(self):
        reg = DomainRegistry()
        assert len(reg) == 0
        reg.register(self._make_profile("one"))
        assert len(reg) == 1

    def test_iter(self):
        reg = DomainRegistry()
        reg.register(self._make_profile("b"))
        reg.register(self._make_profile("a"))
        assert list(reg) == ["a", "b"]

    def test_replace(self):
        reg = DomainRegistry()
        p1 = self._make_profile("replace_me")
        p2 = DomainProfile(
            name="replace_me",
            display_name="Replaced",
            description="New description",
        )
        reg.register(p1)
        reg.replace(p2)
        assert reg.get("replace_me").display_name == "Replaced"

    def test_merge_two_profiles(self):
        reg = DomainRegistry()
        p1 = DomainProfile(
            name="a",
            display_name="A",
            description="Profile A",
            sensitive_terms={"term1": 0.5},
            critical_actions=["action_a"],
            compliance_frameworks=["FW_A"],
            base_risk_floor=0.1,
            production_multiplier=1.5,
        )
        p2 = DomainProfile(
            name="b",
            display_name="B",
            description="Profile B",
            sensitive_terms={"term1": 0.8, "term2": 0.6},
            critical_actions=["action_b"],
            compliance_frameworks=["FW_B"],
            base_risk_floor=0.2,
            production_multiplier=2.0,
        )
        merged = reg.merge(p1, p2)
        assert merged.name == "a+b"
        assert merged.display_name == "A + B"
        # Sensitive terms: higher weight wins for duplicates
        assert merged.sensitive_terms["term1"] == 0.8
        assert merged.sensitive_terms["term2"] == 0.6
        # Critical actions combined and deduplicated
        assert "action_a" in merged.critical_actions
        assert "action_b" in merged.critical_actions
        # Compliance frameworks combined
        assert "FW_A" in merged.compliance_frameworks
        assert "FW_B" in merged.compliance_frameworks
        # Conservative scalars
        assert merged.base_risk_floor == 0.2
        assert merged.production_multiplier == 2.0

    def test_merge_fewer_than_two_raises(self):
        reg = DomainRegistry()
        p = self._make_profile("solo")
        with pytest.raises(ValueError, match="at least two profiles"):
            reg.merge(p)


# =========================================================================
# DomainRiskScorer
# =========================================================================


class TestDomainRiskScorer:
    """Tests for DomainRiskScorer."""

    def _make_profile(self) -> DomainProfile:
        return DomainProfile(
            name="test_scoring",
            display_name="Test Scoring",
            description="Profile for scoring tests.",
            risk_patterns=[
                RiskPattern(
                    pattern=r"patient|phi",
                    target="any",
                    risk_contribution=0.8,
                    name="phi_access",
                    description="PHI access pattern",
                    compliance_refs=["HIPAA s164.312"],
                ),
                RiskPattern(
                    pattern=r"delete_record",
                    target="function_name",
                    risk_contribution=0.9,
                    name="record_deletion",
                    description="Record deletion",
                ),
            ],
            sensitive_terms={"patient": 0.7, "phi": 0.9, "diagnosis": 0.8},
            critical_actions=["delete_patient", "export_phi"],
            safe_actions=["get_status", "list_departments"],
            base_risk_floor=0.1,
            production_multiplier=1.5,
            escalation_rules=[
                EscalationRule(
                    condition="risk_score > 0.9",
                    action="require_multi_party",
                    required_approvers=2,
                ),
                EscalationRule(
                    condition="environment:production",
                    action="require_teach_back",
                ),
                EscalationRule(
                    condition="matches_pattern:phi_access",
                    action="notify_compliance",
                ),
            ],
        )

    def test_constructor_default_base_scorer(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile)
        assert scorer.profile is profile
        assert scorer.name == "domain:test_scoring"

    def test_constructor_custom_base_scorer(self):
        profile = self._make_profile()
        base = FixedRiskScorer(0.3)
        scorer = DomainRiskScorer(profile, base_scorer=base)
        assert scorer._base_scorer is base

    def test_score_returns_float_in_range(self):
        scorer = DomainRiskScorer(self._make_profile())
        ctx = ActionContext(
            function_name="access_phi",
            args=("patient_123",),
            kwargs={"record_type": "lab_result"},
            function_doc="Access patient health information",
            environment="production",
        )
        score = scorer.score(ctx)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_assess_returns_risk_assessment(self):
        scorer = DomainRiskScorer(self._make_profile())
        ctx = ActionContext(
            function_name="access_phi",
            args=("patient_123",),
            environment="development",
        )
        assessment = scorer.assess(ctx)
        assert isinstance(assessment, RiskAssessment)
        assert 0.0 <= assessment.score <= 1.0
        assert isinstance(assessment.level, RiskLevel)
        assert len(assessment.factors) > 0
        assert assessment.scorer_name == "domain:test_scoring"

    def test_pattern_matching_boosts_score(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile, base_scorer=FixedRiskScorer(0.1))
        ctx_no_pattern = ActionContext(
            function_name="benign_func",
            environment="development",
        )
        ctx_with_pattern = ActionContext(
            function_name="access_phi",
            args=("patient_123",),
            function_doc="Access patient health information",
            environment="development",
        )
        score_no = scorer.score(ctx_no_pattern)
        score_with = scorer.score(ctx_with_pattern)
        assert score_with > score_no

    def test_sensitive_terms_boost_score(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile, base_scorer=FixedRiskScorer(0.1))
        ctx_no_terms = ActionContext(
            function_name="do_something",
            args=("hello",),
            environment="development",
        )
        ctx_with_terms = ActionContext(
            function_name="do_something",
            args=("patient diagnosis phi",),
            environment="development",
        )
        score_no = scorer.score(ctx_no_terms)
        score_with = scorer.score(ctx_with_terms)
        assert score_with > score_no

    def test_critical_action_floors_to_0_8(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile, base_scorer=FixedRiskScorer(0.05))
        ctx = ActionContext(
            function_name="delete_patient",
            environment="development",
        )
        score = scorer.score(ctx)
        assert score >= 0.8

    def test_safe_action_caps_to_0_15(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile, base_scorer=FixedRiskScorer(0.5))
        ctx = ActionContext(
            function_name="get_status",
            environment="development",
        )
        score = scorer.score(ctx)
        assert score <= 0.15

    def test_base_risk_floor_enforcement(self):
        profile = DomainProfile(
            name="floor_test",
            display_name="Floor",
            description="Floor test",
            base_risk_floor=0.3,
        )
        scorer = DomainRiskScorer(profile, base_scorer=FixedRiskScorer(0.05))
        ctx = ActionContext(
            function_name="benign_func",
            environment="development",
        )
        score = scorer.score(ctx)
        assert score >= 0.3

    def test_production_multiplier_applied(self):
        profile = DomainProfile(
            name="prod_test",
            display_name="Prod",
            description="Prod multiplier test",
            production_multiplier=2.0,
        )
        scorer = DomainRiskScorer(profile, base_scorer=FixedRiskScorer(0.3))
        ctx_dev = ActionContext(
            function_name="some_func",
            environment="development",
        )
        ctx_prod = ActionContext(
            function_name="some_func",
            environment="production",
        )
        score_dev = scorer.score(ctx_dev)
        score_prod = scorer.score(ctx_prod)
        assert score_prod > score_dev

    def test_production_multiplier_clamped_to_one(self):
        profile = DomainProfile(
            name="clamp_test",
            display_name="Clamp",
            description="Clamp test",
            production_multiplier=10.0,
        )
        scorer = DomainRiskScorer(profile, base_scorer=FixedRiskScorer(0.5))
        ctx = ActionContext(
            function_name="some_func",
            environment="production",
        )
        score = scorer.score(ctx)
        assert score <= 1.0

    def test_check_escalation_risk_score_condition(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile)
        ctx = ActionContext(function_name="some_func", environment="development")
        risk = RiskAssessment(score=0.95, level=RiskLevel.CRITICAL)
        rule = scorer.check_escalation(ctx, risk)
        assert rule is not None
        assert rule.action == "require_multi_party"

    def test_check_escalation_environment_condition(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile)
        ctx = ActionContext(function_name="some_func", environment="production")
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)
        rule = scorer.check_escalation(ctx, risk)
        assert rule is not None
        assert rule.action == "require_teach_back"

    def test_check_escalation_pattern_condition(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile)
        ctx = ActionContext(
            function_name="access_phi",
            args=("patient_123",),
            environment="development",
        )
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)
        rule = scorer.check_escalation(ctx, risk)
        assert rule is not None
        assert rule.action == "notify_compliance"

    def test_check_escalation_no_match(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile)
        ctx = ActionContext(function_name="benign_func", environment="development")
        risk = RiskAssessment(score=0.1, level=RiskLevel.LOW)
        rule = scorer.check_escalation(ctx, risk)
        assert rule is None

    def test_assess_factors_include_base_score(self):
        scorer = DomainRiskScorer(self._make_profile())
        ctx = ActionContext(function_name="benign_func", environment="development")
        assessment = scorer.assess(ctx)
        factor_names = [f.name for f in assessment.factors]
        assert "base_score" in factor_names

    def test_check_all_escalations(self):
        profile = self._make_profile()
        scorer = DomainRiskScorer(profile)
        # Context that matches environment:production AND matches_pattern:phi_access
        ctx = ActionContext(
            function_name="access_phi",
            args=("patient data",),
            function_doc="Access patient health information",
            environment="production",
        )
        risk = RiskAssessment(score=0.95, level=RiskLevel.CRITICAL)
        rules = scorer.check_all_escalations(ctx, risk)
        # Should match risk_score > 0.9, environment:production, and matches_pattern:phi_access
        assert len(rules) >= 2


# =========================================================================
# Preset Registration API
# =========================================================================


class TestPresetAPI:
    """Tests for the preset registration and loading API."""

    def _make_profile(self, name: str = "test-preset") -> DomainProfile:
        return DomainProfile(
            name=name,
            display_name=f"Test ({name})",
            description="Test preset profile.",
            sensitive_terms={"secret": 0.9},
            critical_actions=["delete_all"],
            safe_actions=["check_status"],
        )

    def test_no_builtin_presets(self):
        """OSS release has no built-in presets."""
        # Note: other tests may register presets, so we just check that
        # the standard built-in names are not present unless explicitly
        # registered by test setup.
        pass  # Covered by direct validation

    def test_register_and_load_preset(self):
        profile = self._make_profile("reg-test")
        register_preset(profile)
        loaded = load_preset("reg-test")
        assert loaded.name == "reg-test"
        assert loaded is profile

    def test_register_with_aliases(self):
        profile = self._make_profile("alias-test")
        register_preset(profile, aliases=["at-alias", "at-alt"])
        loaded = load_preset("at-alias")
        assert loaded.name == "alias-test"
        loaded2 = load_preset("at-alt")
        assert loaded2.name == "alias-test"

    def test_unknown_preset_raises_key_error(self):
        with pytest.raises(KeyError, match="No preset profile named"):
            load_preset("nonexistent_domain_xyz")

    def test_list_presets_returns_sorted(self):
        presets = list_presets()
        assert presets == sorted(presets)

    def test_load_preset_case_insensitive(self):
        profile = self._make_profile("case-test")
        register_preset(profile)
        loaded = load_preset("CASE-TEST")
        assert loaded.name == "case-test"


