"""Tests for configuration loader (attesta.config.loader)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from attesta.config.loader import Policy, _parse_config, load_config
from attesta.core.types import ChallengeType, RiskLevel


# ---------------------------------------------------------------------------
# Policy defaults
# ---------------------------------------------------------------------------

class TestPolicyDefaults:
    def test_default_challenge_map(self):
        policy = Policy()
        assert policy.challenge_for_risk(RiskLevel.LOW) == ChallengeType.AUTO_APPROVE
        assert policy.challenge_for_risk(RiskLevel.MEDIUM) == ChallengeType.CONFIRM
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.QUIZ
        # Default: CRITICAL with 2 multi-party => MULTI_PARTY
        assert policy.challenge_for_risk(RiskLevel.CRITICAL) == ChallengeType.MULTI_PARTY

    def test_to_challenge_map(self):
        policy = Policy()
        cmap = policy.to_challenge_map()
        assert len(cmap) == 4
        assert cmap[RiskLevel.LOW] == ChallengeType.AUTO_APPROVE
        assert cmap[RiskLevel.CRITICAL] == ChallengeType.MULTI_PARTY

    def test_min_review_time_defaults(self):
        policy = Policy()
        assert policy.min_review_time(RiskLevel.LOW) == 0
        assert policy.min_review_time(RiskLevel.MEDIUM) == 3
        assert policy.min_review_time(RiskLevel.HIGH) == 10
        assert policy.min_review_time(RiskLevel.CRITICAL) == 30

    def test_domain_strict_default_enabled(self):
        policy = Policy()
        assert policy.domain_strict is True


# ---------------------------------------------------------------------------
# Challenge map overrides (P1.1)
# ---------------------------------------------------------------------------

class TestChallengeMapOverrides:
    def test_override_high_to_teach_back(self):
        policy = Policy(challenge_map_overrides={"high": "teach_back"})
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.TEACH_BACK
        # Other levels unchanged
        assert policy.challenge_for_risk(RiskLevel.LOW) == ChallengeType.AUTO_APPROVE
        assert policy.challenge_for_risk(RiskLevel.MEDIUM) == ChallengeType.CONFIRM

    def test_kebab_case_tokens_accepted(self):
        policy = Policy(challenge_map_overrides={
            "high": "teach-back",
            "critical": "multi-party",
        })
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.TEACH_BACK
        assert policy.challenge_for_risk(RiskLevel.CRITICAL) == ChallengeType.MULTI_PARTY

    def test_snake_case_tokens_accepted(self):
        policy = Policy(challenge_map_overrides={
            "low": "auto_approve",
            "medium": "confirm",
            "high": "quiz",
            "critical": "multi_party",
        })
        assert policy.challenge_for_risk(RiskLevel.LOW) == ChallengeType.AUTO_APPROVE
        assert policy.challenge_for_risk(RiskLevel.MEDIUM) == ChallengeType.CONFIRM
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.QUIZ
        assert policy.challenge_for_risk(RiskLevel.CRITICAL) == ChallengeType.MULTI_PARTY

    def test_unknown_token_falls_back_to_default(self):
        policy = Policy(challenge_map_overrides={"high": "nonexistent_challenge"})
        # Should warn and fall back to default (QUIZ for HIGH)
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.QUIZ

    def test_partial_override(self):
        """Only the overridden level should change; others keep defaults."""
        policy = Policy(challenge_map_overrides={"medium": "quiz"})
        assert policy.challenge_for_risk(RiskLevel.LOW) == ChallengeType.AUTO_APPROVE
        assert policy.challenge_for_risk(RiskLevel.MEDIUM) == ChallengeType.QUIZ
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.QUIZ
        assert policy.challenge_for_risk(RiskLevel.CRITICAL) == ChallengeType.MULTI_PARTY


# ---------------------------------------------------------------------------
# Config parsing (_parse_config)
# ---------------------------------------------------------------------------

class TestParseConfig:
    def test_empty_config(self):
        policy = _parse_config({})
        assert isinstance(policy, Policy)
        assert policy.fail_mode == "deny"

    def test_none_config(self):
        policy = _parse_config(None)
        assert isinstance(policy, Policy)

    def test_policy_section(self):
        data = {
            "policy": {
                "minimum_review_seconds": {"low": 0, "medium": 5, "high": 15, "critical": 60},
                "require_multi_party": {"critical": 3},
                "fail_mode": "escalate",
                "timeout_seconds": 600,
            },
        }
        policy = _parse_config(data)
        assert policy.minimum_review_seconds["critical"] == 60
        assert policy.require_multi_party["critical"] == 3
        assert policy.fail_mode == "escalate"
        assert policy.timeout_seconds == 600

    def test_challenge_map_from_yaml(self):
        data = {
            "policy": {
                "challenge_map": {
                    "high": "teach_back",
                    "critical": "multi_party",
                },
            },
        }
        policy = _parse_config(data)
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.TEACH_BACK
        assert policy.challenge_for_risk(RiskLevel.CRITICAL) == ChallengeType.MULTI_PARTY

    def test_challenges_alias(self):
        """The 'challenges' key should also be accepted."""
        data = {
            "policy": {
                "challenges": {
                    "medium": "quiz",
                },
            },
        }
        policy = _parse_config(data)
        assert policy.challenge_for_risk(RiskLevel.MEDIUM) == ChallengeType.QUIZ

    def test_risk_section(self):
        data = {
            "risk": {
                "overrides": {"deploy_prod": "critical"},
                "amplifiers": [{"pattern": ".*production.*", "boost": 0.3}],
            },
        }
        policy = _parse_config(data)
        assert policy.risk_overrides["deploy_prod"] == "critical"
        assert len(policy.risk_amplifiers) == 1

    def test_trust_section(self):
        data = {
            "trust": {
                "influence": 0.5,
                "ceiling": 0.85,
                "initial_score": 0.4,
                "decay_rate": 0.02,
            },
        }
        policy = _parse_config(data)
        assert policy.trust_influence == 0.5
        assert policy.trust_ceiling == 0.85
        assert policy.trust_initial == 0.4
        assert policy.trust_decay_rate == 0.02

    def test_domain_string(self):
        data = {"domain": "my-domain"}
        policy = _parse_config(data)
        assert policy.domain == "my-domain"

    def test_domain_list(self):
        data = {"domain": ["profile-a", "profile-b"]}
        policy = _parse_config(data)
        assert policy.domain == ["profile-a", "profile-b"]

    def test_domain_strict_defaults_to_true(self):
        data = {"domain": "my-domain"}
        policy = _parse_config(data)
        assert policy.domain_strict is True

    def test_domain_strict_can_be_disabled(self):
        data = {"domain": "my-domain", "domain_strict": False}
        policy = _parse_config(data)
        assert policy.domain_strict is False

    def test_to_trust_engine_kwargs(self):
        policy = Policy(trust_initial=0.5, trust_ceiling=0.8, trust_decay_rate=0.05, trust_influence=0.4)
        kwargs = policy.to_trust_engine_kwargs()
        assert kwargs == {
            "initial_score": 0.5,
            "ceiling": 0.8,
            "decay_rate": 0.05,
            "influence": 0.4,
        }


# ---------------------------------------------------------------------------
# load_config with YAML files
# ---------------------------------------------------------------------------

class TestLoadConfigYAML:
    def test_missing_file_returns_defaults(self, tmp_path: Path):
        policy = load_config(tmp_path / "nonexistent.yaml")
        assert isinstance(policy, Policy)
        assert policy.fail_mode == "deny"

    def test_unsupported_format_raises(self, tmp_path: Path):
        bad = tmp_path / "config.json"
        bad.write_text("{}")
        with pytest.raises(ValueError, match="Unsupported config format"):
            load_config(bad)

    def test_yaml_round_trip(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""\
            policy:
              minimum_review_seconds:
                low: 0
                medium: 5
                high: 15
                critical: 45
              challenge_map:
                high: teach_back
              fail_mode: deny

            risk:
              overrides:
                deploy_production: critical

            trust:
              influence: 0.25
              ceiling: 0.85
        """)
        yaml_file = tmp_path / "attesta.yaml"
        yaml_file.write_text(yaml_content)
        policy = load_config(yaml_file)

        assert policy.minimum_review_seconds["critical"] == 45
        assert policy.challenge_for_risk(RiskLevel.HIGH) == ChallengeType.TEACH_BACK
        assert policy.risk_overrides["deploy_production"] == "critical"
        assert policy.trust_influence == 0.25
        assert policy.trust_ceiling == 0.85


# ---------------------------------------------------------------------------
# Domain scorer strictness
# ---------------------------------------------------------------------------

class TestDomainScorerStrictness:
    def test_missing_domain_raises_by_default(self):
        policy = Policy(domain="nonexistent_domain_xyz_123")
        with pytest.raises(KeyError):
            policy.build_risk_scorer()

    def test_missing_domain_can_fallback_when_disabled(self):
        policy = Policy(
            domain="nonexistent_domain_xyz_123",
            domain_strict=False,
        )
        scorer = policy.build_risk_scorer()
        assert scorer is None
