"""Tests for attesta.challenges.validators."""

from __future__ import annotations

from attesta.challenges.validators import (
    KeywordValidator,
    TeachBackValidator,
)
from attesta.core.types import ActionContext

# =========================================================================
# KeywordValidator
# =========================================================================


class TestKeywordValidator:
    async def test_passes_with_enough_words_and_key_terms(self):
        ctx = ActionContext(function_name="deploy_service", args=("web",))
        v = KeywordValidator(min_words=3)
        passed, notes = await v.validate("I will deploy the web service to production", ctx)
        assert passed is True
        assert "Matched key terms" in notes

    async def test_fails_too_short(self):
        ctx = ActionContext(function_name="deploy_service")
        v = KeywordValidator(min_words=10)
        passed, notes = await v.validate("deploy it", ctx)
        assert passed is False
        assert "Too short" in notes

    async def test_fails_no_key_terms(self):
        ctx = ActionContext(function_name="deploy_service")
        v = KeywordValidator(min_words=2)
        passed, notes = await v.validate("I will do something unrelated to anything here", ctx)
        assert passed is False
        assert "No key terms" in notes

    async def test_default_min_words_is_15(self):
        v = KeywordValidator()
        assert v.min_words == 15

    async def test_satisfies_protocol(self):
        v = KeywordValidator()
        assert isinstance(v, TeachBackValidator)
