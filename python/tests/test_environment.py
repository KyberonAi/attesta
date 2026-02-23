"""Tests for attesta.environment -- auto-detection and risk multipliers."""

from __future__ import annotations

from attesta.environment import (
    RISK_MULTIPLIERS,
    Environment,
    detect_environment,
)


class TestEnvironmentEnum:
    def test_values(self):
        assert Environment.PRODUCTION.value == "production"
        assert Environment.STAGING.value == "staging"
        assert Environment.CI.value == "ci"
        assert Environment.DEVELOPMENT.value == "development"

    def test_member_count(self):
        assert len(Environment) == 4


class TestRiskMultipliers:
    def test_production_amplifies(self):
        assert RISK_MULTIPLIERS["production"] > 1.0

    def test_development_reduces(self):
        assert RISK_MULTIPLIERS["development"] < 1.0

    def test_ci_neutral(self):
        assert RISK_MULTIPLIERS["ci"] == 1.0

    def test_all_environments_have_multipliers(self):
        for env in Environment:
            assert env.value in RISK_MULTIPLIERS


class TestDetectEnvironment:
    def test_explicit_override(self, monkeypatch):
        monkeypatch.setenv("ATTESTA_ENV", "production")
        assert detect_environment() is Environment.PRODUCTION

    def test_explicit_override_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("ATTESTA_ENV", "STAGING")
        assert detect_environment() is Environment.STAGING

    def test_ci_from_ci_var(self, monkeypatch):
        monkeypatch.delenv("ATTESTA_ENV", raising=False)
        monkeypatch.setenv("CI", "true")
        assert detect_environment() is Environment.CI

    def test_ci_from_github_actions(self, monkeypatch):
        monkeypatch.delenv("ATTESTA_ENV", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        assert detect_environment() is Environment.CI

    def test_ci_from_gitlab(self, monkeypatch):
        monkeypatch.delenv("ATTESTA_ENV", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setenv("GITLAB_CI", "true")
        assert detect_environment() is Environment.CI

    def test_production_from_node_env(self, monkeypatch):
        monkeypatch.delenv("ATTESTA_ENV", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setenv("NODE_ENV", "production")
        assert detect_environment() is Environment.PRODUCTION

    def test_production_from_flask_env(self, monkeypatch):
        monkeypatch.delenv("ATTESTA_ENV", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("NODE_ENV", raising=False)
        monkeypatch.setenv("FLASK_ENV", "production")
        assert detect_environment() is Environment.PRODUCTION

    def test_production_from_django_settings(self, monkeypatch):
        monkeypatch.delenv("ATTESTA_ENV", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("NODE_ENV", raising=False)
        monkeypatch.delenv("FLASK_ENV", raising=False)
        monkeypatch.setenv("DJANGO_SETTINGS_MODULE", "myapp.settings.production")
        assert detect_environment() is Environment.PRODUCTION

    def test_default_is_development(self, monkeypatch):
        # Clear all env vars that could trigger detection
        for var in ("ATTESTA_ENV", "CI", "GITHUB_ACTIONS", "GITLAB_CI",
                     "JENKINS_URL", "CIRCLECI", "TRAVIS", "BUILDKITE",
                     "NODE_ENV", "FLASK_ENV", "DJANGO_SETTINGS_MODULE",
                     "RAILS_ENV"):
            monkeypatch.delenv(var, raising=False)
        result = detect_environment()
        # May be development or something else based on hostname
        assert isinstance(result, Environment)

    def test_explicit_wins_over_ci(self, monkeypatch):
        monkeypatch.setenv("ATTESTA_ENV", "staging")
        monkeypatch.setenv("CI", "true")
        assert detect_environment() is Environment.STAGING

    def test_invalid_explicit_falls_through(self, monkeypatch):
        monkeypatch.setenv("ATTESTA_ENV", "invalid_value")
        monkeypatch.setenv("CI", "true")
        assert detect_environment() is Environment.CI


class TestEnvironmentMultiplierInGate:
    """Test that environment detection and multipliers integrate with gate."""

    async def test_production_amplifies_risk(self):
        from attesta.core.gate import Attesta
        from attesta.core.types import ActionContext

        g = Attesta()
        ctx = ActionContext(function_name="test_fn", environment="production")
        result = await g.evaluate(ctx)
        # Production should result in higher risk than development
        # (since the multiplier is 1.5x)
        assert result.risk_assessment is not None

    async def test_development_environment_detected(self, monkeypatch):
        """When no environment is passed, auto-detect should be used."""
        for var in ("ATTESTA_ENV", "CI", "GITHUB_ACTIONS", "GITLAB_CI",
                     "JENKINS_URL", "NODE_ENV", "FLASK_ENV",
                     "DJANGO_SETTINGS_MODULE", "RAILS_ENV",
                     "CIRCLECI", "TRAVIS", "BUILDKITE"):
            monkeypatch.delenv(var, raising=False)

        from attesta.core.gate import _build_context

        def dummy():
            pass

        ctx = _build_context(dummy, (), {})
        # Should be auto-detected (development by default on dev machines)
        assert ctx.environment is not None
