"""Security regression tests for the Attesta framework.

This module tests all security-related fixes across the codebase:

1. XSS escaping in WebRenderer HTML output
2. CSRF token validation on POST requests
3. POST body size limits (64KB max)
4. risk_override hint guard (allow_hint_override flag)
5. EOFError handling in challenge modules (stdin closed)
6. Approval timeout returning Verdict.TIMED_OUT
7. Audit chain verification with malformed entries
8. Audit file permissions (0o600)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from attesta.core.audit import AuditEntry, AuditLogger, _GENESIS_HASH
from attesta.core.gate import Attesta, TRUSTED_RISK_OVERRIDE_METADATA_KEY
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
from attesta.renderers.web import (
    WebRenderer,
    _confirm_page,
    _esc,
    _teach_back_page,
)


# =========================================================================
# Shared test helpers
# =========================================================================


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get_csrf_token(port: int) -> str:
    """Fetch the rendered page and extract the CSRF token."""
    resp = urlopen(f"http://127.0.0.1:{port}", timeout=5)
    html = resp.read().decode("utf-8")
    match = re.search(r'name="_csrf"\s+value="([^"]+)"', html)
    assert match, "CSRF token not found in rendered HTML"
    return match.group(1)


class _ApproveAllRenderer:
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


class _SlowRenderer:
    """Mock renderer that never responds (simulates timeout)."""

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


class _RecordingAuditLogger:
    """Mock audit logger that records calls."""

    def __init__(self):
        self.entries: list[tuple[ActionContext, ApprovalResult]] = []

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        self.entries.append((ctx, result))
        return f"test-audit-{len(self.entries)}"


# =========================================================================
# 1. XSS Escaping in WebRenderer
# =========================================================================


class TestXSSEscaping:
    """Verify that user-controlled strings are HTML-escaped in rendered output."""

    def test_esc_helper_escapes_script_tag(self):
        """The _esc() helper must escape angle brackets and quotes."""
        assert _esc("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_esc_helper_escapes_ampersand(self):
        assert _esc("a&b") == "a&amp;b"

    def test_esc_helper_escapes_double_quotes(self):
        assert _esc('value="injected"') == "value=&quot;injected&quot;"

    def test_confirm_page_escapes_function_name(self):
        """Script tags in function_name must be escaped in confirm page HTML."""
        ctx = ActionContext(function_name="<script>alert('xss')</script>")
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)
        html = _confirm_page(ctx, risk)

        # The raw script tag must NOT appear
        assert "<script>alert(" not in html
        # The escaped version must appear
        assert "&lt;script&gt;" in html

    def test_confirm_page_escapes_description(self):
        """HTML in the auto-generated description must be escaped."""
        ctx = ActionContext(
            function_name='<img src=x onerror="alert(1)">',
            args=("normal_arg",),
        )
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)
        html = _confirm_page(ctx, risk)

        assert '<img src=x' not in html
        assert "&lt;img" in html

    def test_confirm_page_escapes_risk_factor_names(self):
        """Risk factor names containing HTML are escaped."""
        ctx = ActionContext(function_name="safe_name")
        risk = RiskAssessment(
            score=0.7,
            level=RiskLevel.HIGH,
            factors=[
                RiskFactor(
                    name='<b onmouseover="alert(1)">factor</b>',
                    contribution=0.5,
                    description="normal description",
                ),
            ],
        )
        html = _confirm_page(ctx, risk)
        assert '<b onmouseover=' not in html
        assert "&lt;b onmouseover=" in html

    def test_confirm_page_escapes_risk_factor_descriptions(self):
        """Risk factor descriptions containing HTML are escaped."""
        ctx = ActionContext(function_name="safe_name")
        risk = RiskAssessment(
            score=0.7,
            level=RiskLevel.HIGH,
            factors=[
                RiskFactor(
                    name="legitimate_factor",
                    contribution=0.5,
                    description='<script>document.cookie</script>',
                ),
            ],
        )
        html = _confirm_page(ctx, risk)
        assert "<script>document.cookie</script>" not in html
        assert "&lt;script&gt;document.cookie&lt;/script&gt;" in html

    def test_teach_back_page_escapes_function_name(self):
        """Script tags in function_name must be escaped in teach-back page."""
        ctx = ActionContext(
            function_name="<script>alert('xss')</script>",
            function_doc="<b>bold doc</b>",
        )
        risk = RiskAssessment(score=0.9, level=RiskLevel.CRITICAL)
        html = _teach_back_page(ctx, risk, min_review=0)

        assert "<script>alert(" not in html
        assert "&lt;script&gt;" in html
        # function_doc should also be escaped
        assert "<b>bold doc</b>" not in html
        assert "&lt;b&gt;bold doc&lt;/b&gt;" in html

    def test_teach_back_page_escapes_risk_factors(self):
        """Risk factor fields in teach-back page are escaped."""
        ctx = ActionContext(function_name="safe_fn")
        risk = RiskAssessment(
            score=0.9,
            level=RiskLevel.CRITICAL,
            factors=[
                RiskFactor(
                    name='<div onclick="evil()">',
                    contribution=0.8,
                    description='<a href="javascript:void(0)">click</a>',
                ),
            ],
        )
        html = _teach_back_page(ctx, risk, min_review=0)
        assert '<div onclick=' not in html
        assert '<a href="javascript:' not in html

    async def test_xss_escaping_via_live_server(self):
        """End-to-end: fetch actual served HTML and verify XSS is escaped."""
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(
            function_name="<script>alert('xss')</script>",
        )
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)

        html_received: list[str] = []

        def fetch_and_submit():
            time.sleep(0.5)
            resp = urlopen(f"http://127.0.0.1:{port}", timeout=5)
            page_html = resp.read().decode("utf-8")
            html_received.append(page_html)
            # Extract CSRF and submit to unblock
            match = re.search(r'name="_csrf"\s+value="([^"]+)"', page_html)
            csrf = match.group(1) if match else ""
            time.sleep(0.1)
            data = urlencode({"verdict": "approve", "_csrf": csrf}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            urlopen(req, timeout=5)

        thread = threading.Thread(target=fetch_and_submit, daemon=True)
        thread.start()

        await renderer.render_approval(ctx, risk)
        assert len(html_received) == 1
        assert "<script>alert(" not in html_received[0]
        assert "&lt;script&gt;" in html_received[0]


# =========================================================================
# 2. CSRF Token Validation
# =========================================================================


class TestCSRFTokenValidation:
    """Verify that POST requests without a valid CSRF token are rejected."""

    async def test_missing_csrf_token_returns_403(self):
        """POST with no CSRF token at all should be rejected with 403."""
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="test_csrf_missing")
        risk = RiskAssessment(score=0.4, level=RiskLevel.MEDIUM)

        rejection_status: list[int | None] = []

        def submit():
            time.sleep(0.5)
            # POST without any CSRF token
            data = urlencode({"verdict": "approve"}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            try:
                urlopen(req, timeout=5)
            except Exception as e:
                rejection_status.append(getattr(e, "code", None))

            # Now submit with valid token to unblock
            time.sleep(0.2)
            csrf = _get_csrf_token(port)
            data = urlencode({"verdict": "approve", "_csrf": csrf}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert verdict == Verdict.APPROVED
        assert 403 in rejection_status

    async def test_wrong_csrf_token_returns_403(self):
        """POST with an incorrect CSRF token should be rejected with 403."""
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="test_csrf_wrong")
        risk = RiskAssessment(score=0.4, level=RiskLevel.MEDIUM)

        rejection_status: list[int | None] = []

        def submit():
            time.sleep(0.5)
            # POST with a fabricated token
            data = urlencode(
                {"verdict": "approve", "_csrf": "forged-token-value"}
            ).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            try:
                urlopen(req, timeout=5)
            except Exception as e:
                rejection_status.append(getattr(e, "code", None))

            # Unblock with valid token
            time.sleep(0.2)
            csrf = _get_csrf_token(port)
            data = urlencode({"verdict": "approve", "_csrf": csrf}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert verdict == Verdict.APPROVED
        assert 403 in rejection_status

    async def test_valid_csrf_token_accepted(self):
        """POST with the correct CSRF token should succeed (200)."""
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="test_csrf_valid")
        risk = RiskAssessment(score=0.4, level=RiskLevel.MEDIUM)

        def submit():
            time.sleep(0.5)
            csrf = _get_csrf_token(port)
            data = urlencode({"verdict": "approve", "_csrf": csrf}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert verdict == Verdict.APPROVED

    async def test_csrf_token_is_unique_per_session(self):
        """Each call to _serve_and_wait generates a fresh CSRF token."""
        port1 = _find_free_port()
        renderer1 = WebRenderer(port=port1, auto_open=False)

        port2 = _find_free_port()
        renderer2 = WebRenderer(port=port2, auto_open=False)

        ctx = ActionContext(function_name="test_unique_csrf")
        risk = RiskAssessment(score=0.4, level=RiskLevel.MEDIUM)

        tokens: list[str] = []

        def fetch_token_and_submit(port: int):
            time.sleep(0.5)
            csrf = _get_csrf_token(port)
            tokens.append(csrf)
            data = urlencode({"verdict": "approve", "_csrf": csrf}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            urlopen(req, timeout=5)

        t1 = threading.Thread(
            target=fetch_token_and_submit, args=(port1,), daemon=True
        )
        t2 = threading.Thread(
            target=fetch_token_and_submit, args=(port2,), daemon=True
        )

        t1.start()
        t2.start()

        await asyncio.gather(
            renderer1.render_approval(ctx, risk),
            renderer2.render_approval(ctx, risk),
        )
        assert len(tokens) == 2
        assert tokens[0] != tokens[1], "CSRF tokens must be unique per session"


# =========================================================================
# 3. POST Body Size Limit
# =========================================================================


class TestBodySizeLimit:
    """Verify that POST bodies exceeding 64KB are rejected with 413."""

    async def test_oversized_body_returns_413(self):
        """A POST body larger than 64KB should be rejected."""
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="test_body_limit")
        risk = RiskAssessment(score=0.4, level=RiskLevel.MEDIUM)

        rejection_status: list[int | None] = []

        def submit_large_body():
            time.sleep(0.5)
            # 70,000 bytes > 65,536 (64KB)
            large_data = ("x" * 70000).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond",
                data=large_data,
                method="POST",
            )
            req.add_header("Content-Length", str(len(large_data)))
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            try:
                urlopen(req, timeout=5)
            except Exception as e:
                rejection_status.append(getattr(e, "code", None))

            # Unblock with a valid small request
            time.sleep(0.2)
            csrf = _get_csrf_token(port)
            data = urlencode({"verdict": "approve", "_csrf": csrf}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit_large_body, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert verdict == Verdict.APPROVED
        assert 413 in rejection_status

    async def test_body_at_exact_limit_is_accepted(self):
        """A POST body of exactly 65536 bytes should be accepted (not rejected)."""
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="test_body_exact")
        risk = RiskAssessment(score=0.4, level=RiskLevel.MEDIUM)

        response_codes: list[int] = []

        def submit_exact_body():
            time.sleep(0.5)
            csrf = _get_csrf_token(port)
            # Build a payload that is exactly 65536 bytes
            base = urlencode({"verdict": "approve", "_csrf": csrf})
            padding_needed = 65536 - len(base) - len("&pad=")
            if padding_needed > 0:
                padded_data = (base + "&pad=" + "x" * padding_needed).encode()
            else:
                padded_data = base.encode()
            # Ensure it does not exceed the limit
            padded_data = padded_data[:65536]
            req = Request(
                f"http://127.0.0.1:{port}/respond",
                data=padded_data,
                method="POST",
            )
            req.add_header("Content-Length", str(len(padded_data)))
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            try:
                resp = urlopen(req, timeout=5)
                response_codes.append(resp.status)
            except Exception as e:
                response_codes.append(getattr(e, "code", 0))

        thread = threading.Thread(target=submit_exact_body, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert len(response_codes) == 1
        # Should be 200 (accepted), not 413
        assert response_codes[0] == 200

    async def test_body_just_over_limit_is_rejected(self):
        """A POST body of 65537 bytes (1 over limit) should be rejected."""
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="test_body_over")
        risk = RiskAssessment(score=0.4, level=RiskLevel.MEDIUM)

        rejection_status: list[int | None] = []

        def submit():
            time.sleep(0.5)
            # 65537 bytes = 1 byte over the 64KB limit
            data = ("x" * 65537).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond",
                data=data,
                method="POST",
            )
            req.add_header("Content-Length", str(len(data)))
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            try:
                urlopen(req, timeout=5)
            except Exception as e:
                rejection_status.append(getattr(e, "code", None))

            # Unblock
            time.sleep(0.2)
            csrf = _get_csrf_token(port)
            data = urlencode({"verdict": "approve", "_csrf": csrf}).encode()
            req = Request(
                f"http://127.0.0.1:{port}/respond", data=data, method="POST"
            )
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert verdict == Verdict.APPROVED
        assert 413 in rejection_status


# =========================================================================
# 4. risk_override Hint Guard
# =========================================================================


class TestRiskOverrideHintGuard:
    """Verify that hints['risk_override'] is gated by allow_hint_override."""

    async def test_hint_override_ignored_by_default(self):
        """When allow_hint_override=False (default), risk_override hint is ignored."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            audit_logger=_RecordingAuditLogger(),
        )
        ctx = ActionContext(
            function_name="deploy_prod",
            hints={"risk_override": "low"},
        )
        result = await g.evaluate(ctx)

        # The hint should be ignored; the scorer determines the risk level.
        # It should NOT be forced to LOW via the hint.
        assert result.risk_assessment.scorer_name != "override"

    async def test_hint_override_ignored_logs_warning(self):
        """A warning should be logged when hint override is ignored."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            audit_logger=_RecordingAuditLogger(),
        )
        ctx = ActionContext(
            function_name="deploy_prod",
            hints={"risk_override": "low"},
        )

        with patch("attesta.core.gate.logger") as mock_logger:
            await g.evaluate(ctx)
            # The warning about ignored hint should be logged
            mock_logger.warning.assert_called()
            warning_msg = mock_logger.warning.call_args[0][0]
            assert "risk_override" in warning_msg
            assert "allow_hint_override" in warning_msg

    async def test_hint_override_works_when_enabled(self):
        """When allow_hint_override=True, hints['risk_override'] is honoured."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            audit_logger=_RecordingAuditLogger(),
            allow_hint_override=True,
        )
        ctx = ActionContext(
            function_name="deploy_prod",
            hints={"risk_override": "low"},
        )
        result = await g.evaluate(ctx)

        # The hint should override the risk level to LOW.
        # Note: the environment multiplier may adjust the final score
        # slightly, but the scorer_name confirms the override path was taken
        # and the level should remain LOW.
        assert result.risk_assessment.level is RiskLevel.LOW
        assert result.risk_assessment.scorer_name == "override"
        # The base score is 0.15; environment multiplier may adjust it,
        # but it should still be in the LOW range (< 0.3).
        assert result.risk_assessment.score < 0.3

    async def test_hint_override_with_enum_value(self):
        """allow_hint_override accepts RiskLevel enum values in hints."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            allow_hint_override=True,
        )
        # Use "production" environment so the multiplier does not downgrade
        # the CRITICAL level (production multiplier is >= 1.0).
        ctx = ActionContext(
            function_name="deploy_prod",
            hints={"risk_override": RiskLevel.CRITICAL},
            environment="production",
        )
        result = await g.evaluate(ctx)

        # The override path was taken
        assert result.risk_assessment.scorer_name == "override"
        # Verify the base override factor is present with CRITICAL contribution
        factor_names = [f.name for f in result.risk_assessment.factors]
        assert "manual_override" in factor_names

    async def test_constructor_override_takes_precedence_over_hint(self):
        """Constructor risk_override always beats hint risk_override."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            risk_override=RiskLevel.HIGH,
            allow_hint_override=True,
        )
        ctx = ActionContext(
            function_name="deploy_prod",
            hints={"risk_override": "low"},
        )
        result = await g.evaluate(ctx)

        # Constructor override (HIGH) should take precedence
        assert result.risk_assessment.level is RiskLevel.HIGH

    async def test_hint_override_without_hint_set_falls_to_scorer(self):
        """When allow_hint_override=True but no hint is set, scorer is used."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            allow_hint_override=True,
        )
        ctx = ActionContext(function_name="get_user")
        result = await g.evaluate(ctx)

        # Should use the actual scorer, not override
        assert result.risk_assessment.scorer_name != "override"

    async def test_trusted_metadata_override_works_when_hints_disabled(self):
        """Trusted metadata overrides should work even when hint overrides are disabled."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            audit_logger=_RecordingAuditLogger(),
            allow_hint_override=False,
        )
        ctx = ActionContext(
            function_name="drop_database",
            metadata={TRUSTED_RISK_OVERRIDE_METADATA_KEY: "low"},
        )
        result = await g.evaluate(ctx)

        assert result.risk_assessment.scorer_name == "override"
        assert result.risk_assessment.level is RiskLevel.LOW

    async def test_invalid_trusted_metadata_override_is_ignored(self):
        """Invalid trusted overrides should fall back to scorer and log a warning."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            audit_logger=_RecordingAuditLogger(),
            allow_hint_override=False,
        )
        ctx = ActionContext(
            function_name="drop_database",
            metadata={TRUSTED_RISK_OVERRIDE_METADATA_KEY: "super_critical"},
        )

        with patch("attesta.core.gate.logger") as mock_logger:
            result = await g.evaluate(ctx)
            assert result.risk_assessment.scorer_name != "override"
            mock_logger.warning.assert_called()


# =========================================================================
# 5. EOFError Handling in Challenges
# =========================================================================


class TestEOFErrorHandling:
    """Verify that challenge modules handle EOFError gracefully."""

    async def test_confirm_challenge_handles_eof(self):
        """ConfirmChallenge returns passed=False when stdin is closed (EOFError)."""
        from attesta.challenges.confirm import ConfirmChallenge

        challenge = ConfirmChallenge(min_review_seconds=0)
        ctx = ActionContext(function_name="deploy")
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)

        # Mock input() to raise EOFError (simulating closed stdin)
        with patch("builtins.input", side_effect=EOFError):
            result = await challenge.present(ctx, risk)

        assert result.passed is False
        assert result.challenge_type is ChallengeType.CONFIRM

    async def test_confirm_challenge_handles_keyboard_interrupt(self):
        """ConfirmChallenge returns passed=False on KeyboardInterrupt."""
        from attesta.challenges.confirm import ConfirmChallenge

        challenge = ConfirmChallenge(min_review_seconds=0)
        ctx = ActionContext(function_name="deploy")
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = await challenge.present(ctx, risk)

        assert result.passed is False

    async def test_teach_back_challenge_handles_eof(self):
        """TeachBackChallenge returns passed=False when stdin is closed."""
        from attesta.challenges.teach_back import TeachBackChallenge

        challenge = TeachBackChallenge(min_words=5, min_review_seconds=0)
        ctx = ActionContext(function_name="drop_database", args=("users",))
        risk = RiskAssessment(score=0.9, level=RiskLevel.CRITICAL)

        with patch("builtins.input", side_effect=EOFError):
            result = await challenge.present(ctx, risk)

        assert result.passed is False
        assert result.challenge_type is ChallengeType.TEACH_BACK
        # The explanation should be empty
        assert result.details.get("explanation") == ""

    async def test_teach_back_challenge_handles_keyboard_interrupt(self):
        """TeachBackChallenge returns passed=False on KeyboardInterrupt."""
        from attesta.challenges.teach_back import TeachBackChallenge

        challenge = TeachBackChallenge(min_words=5, min_review_seconds=0)
        ctx = ActionContext(function_name="drop_database", args=("users",))
        risk = RiskAssessment(score=0.9, level=RiskLevel.CRITICAL)

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = await challenge.present(ctx, risk)

        assert result.passed is False


# =========================================================================
# 6. Approval Timeout
# =========================================================================


class TestApprovalTimeout:
    """Verify that the approval timeout fires and returns Verdict.TIMED_OUT."""

    async def test_timeout_returns_timed_out_verdict(self):
        """When approval_timeout_seconds expires, verdict is TIMED_OUT."""
        g = Attesta(
            renderer=_SlowRenderer(),
            risk_override=RiskLevel.MEDIUM,
            approval_timeout_seconds=0.3,
        )
        ctx = ActionContext(function_name="slow_action")
        result = await g.evaluate(ctx)

        assert result.verdict is Verdict.TIMED_OUT

    async def test_timeout_has_challenge_result_with_reason(self):
        """Timed-out result includes a challenge_result with a reason."""
        g = Attesta(
            renderer=_SlowRenderer(),
            risk_override=RiskLevel.HIGH,
            approval_timeout_seconds=0.2,
        )
        ctx = ActionContext(function_name="slow_deploy")
        result = await g.evaluate(ctx)

        assert result.verdict is Verdict.TIMED_OUT
        assert result.challenge_result is not None
        assert result.challenge_result.passed is False
        assert "timed out" in result.challenge_result.details.get("reason", "").lower()

    async def test_timeout_not_triggered_when_response_is_fast(self):
        """When response arrives before timeout, verdict is normal."""
        g = Attesta(
            renderer=_ApproveAllRenderer(),
            risk_override=RiskLevel.MEDIUM,
            approval_timeout_seconds=60.0,
        )
        ctx = ActionContext(function_name="fast_action")
        result = await g.evaluate(ctx)

        assert result.verdict is Verdict.APPROVED

    async def test_timeout_does_not_apply_to_auto_approve(self):
        """AUTO_APPROVE (low risk) should not be affected by timeout."""
        g = Attesta(
            renderer=_SlowRenderer(),
            risk_override=RiskLevel.LOW,
            approval_timeout_seconds=0.1,
        )
        ctx = ActionContext(function_name="safe_action")
        result = await g.evaluate(ctx)

        # LOW risk -> AUTO_APPROVE, no challenge, so timeout is irrelevant
        assert result.verdict is Verdict.APPROVED

    async def test_timeout_with_fail_mode_allow_returns_approved(self):
        """fail_mode=allow permits execution when challenge times out."""
        g = Attesta(
            renderer=_SlowRenderer(),
            risk_override=RiskLevel.HIGH,
            fail_mode="allow",
            approval_timeout_seconds=0.1,
        )
        ctx = ActionContext(function_name="allow_on_timeout")
        result = await g.evaluate(ctx)

        assert result.verdict is Verdict.APPROVED
        assert result.challenge_result is not None
        assert result.challenge_result.details["fail_mode"] == "allow"
        assert result.metadata["timed_out"] is True

    async def test_timeout_with_fail_mode_escalate_returns_escalated(self):
        """fail_mode=escalate returns ESCALATED and preserves timeout metadata."""
        g = Attesta(
            renderer=_SlowRenderer(),
            risk_override=RiskLevel.HIGH,
            fail_mode="escalate",
            approval_timeout_seconds=0.1,
        )
        ctx = ActionContext(function_name="escalate_on_timeout")
        result = await g.evaluate(ctx)

        assert result.verdict is Verdict.ESCALATED
        assert result.challenge_result is not None
        assert result.challenge_result.details["fail_mode"] == "escalate"
        assert result.metadata["timed_out"] is True


# =========================================================================
# 7. Audit Chain Verification
# =========================================================================


class TestAuditChainVerification:
    """Verify that verify_chain() handles malformed entries correctly."""

    def test_valid_chain_verifies_intact(self, tmp_path: Path):
        """A properly constructed chain should verify as intact."""
        audit = AuditLogger(path=tmp_path / "audit.jsonl")

        entry1 = AuditEntry(
            action_name="action_1",
            verdict="approved",
            risk_score=0.3,
            risk_level="low",
        )
        entry2 = AuditEntry(
            action_name="action_2",
            verdict="denied",
            risk_score=0.8,
            risk_level="critical",
        )

        audit.log_entry(entry1)
        audit.log_entry(entry2)

        intact, total, broken = audit.verify_chain()
        assert intact is True
        assert total == 2
        assert broken == []

    def test_malformed_json_detected(self, tmp_path: Path):
        """Malformed JSON entries should be flagged without crashing."""
        log_path = tmp_path / "audit.jsonl"

        # Write a valid entry first
        audit = AuditLogger(path=log_path)
        entry1 = AuditEntry(
            action_name="action_1",
            verdict="approved",
            risk_score=0.2,
            risk_level="low",
        )
        audit.log_entry(entry1)

        # Append a malformed JSON line directly
        with log_path.open("a") as f:
            f.write("THIS IS NOT JSON\n")

        # Write another valid entry (its chain will reference the
        # malformed one's hash, which doesn't exist)
        audit2 = AuditLogger(path=log_path)
        entry3 = AuditEntry(
            action_name="action_3",
            verdict="approved",
            risk_score=0.1,
            risk_level="low",
        )
        audit2.log_entry(entry3)

        intact, total, broken = audit2.verify_chain()
        assert intact is False
        assert total >= 2
        # The malformed line index should be in broken
        assert 1 in broken

    def test_tampered_entry_detected(self, tmp_path: Path):
        """An entry with a tampered field should break chain verification."""
        log_path = tmp_path / "audit.jsonl"

        audit = AuditLogger(path=log_path)
        entry1 = AuditEntry(
            action_name="action_1",
            verdict="approved",
            risk_score=0.3,
            risk_level="low",
        )
        entry2 = AuditEntry(
            action_name="action_2",
            verdict="denied",
            risk_score=0.7,
            risk_level="high",
        )
        audit.log_entry(entry1)
        audit.log_entry(entry2)

        # Tamper with the second entry: change the verdict
        lines = log_path.read_text().strip().split("\n")
        tampered = json.loads(lines[1])
        tampered["verdict"] = "approved"  # was "denied"
        lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        log_path.write_text("\n".join(lines) + "\n")

        audit2 = AuditLogger(path=log_path)
        intact, total, broken = audit2.verify_chain()
        assert intact is False
        assert 1 in broken  # Second entry (index 1) should be broken

    def test_empty_log_verifies_intact(self, tmp_path: Path):
        """An empty/missing log file should verify as intact with 0 entries."""
        audit = AuditLogger(path=tmp_path / "nonexistent.jsonl")
        intact, total, broken = audit.verify_chain()
        assert intact is True
        assert total == 0
        assert broken == []

    def test_single_entry_chain_verifies(self, tmp_path: Path):
        """A chain with a single entry should verify correctly."""
        audit = AuditLogger(path=tmp_path / "audit.jsonl")
        entry = AuditEntry(
            action_name="only_action",
            verdict="approved",
            risk_score=0.1,
            risk_level="low",
        )
        audit.log_entry(entry)

        intact, total, broken = audit.verify_chain()
        assert intact is True
        assert total == 1
        assert broken == []

    def test_blank_lines_are_skipped(self, tmp_path: Path):
        """Blank lines in the JSONL file should be silently skipped."""
        log_path = tmp_path / "audit.jsonl"

        audit = AuditLogger(path=log_path)
        entry = AuditEntry(
            action_name="action_1",
            verdict="approved",
            risk_score=0.2,
            risk_level="low",
        )
        audit.log_entry(entry)

        # Append some blank lines
        with log_path.open("a") as f:
            f.write("\n\n\n")

        intact, total, broken = audit.verify_chain()
        assert intact is True
        assert total == 1


# =========================================================================
# 8. Audit File Permissions
# =========================================================================


class TestAuditFilePermissions:
    """Verify that audit files are created with restrictive permissions."""

    def test_new_audit_file_has_600_permissions(self, tmp_path: Path):
        """A newly created audit file should have 0o600 permissions."""
        log_path = tmp_path / "secure_audit.jsonl"
        assert not log_path.exists()

        audit = AuditLogger(path=log_path)
        entry = AuditEntry(
            action_name="first_action",
            verdict="approved",
            risk_score=0.1,
            risk_level="low",
        )
        audit.log_entry(entry)

        assert log_path.exists()
        # Check the file permissions
        file_stat = log_path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        assert mode == 0o600, (
            f"Expected file permissions 0o600, got {oct(mode)}"
        )

    def test_audit_file_not_world_readable(self, tmp_path: Path):
        """The audit file must not be readable by 'other' users."""
        log_path = tmp_path / "audit_perms.jsonl"

        audit = AuditLogger(path=log_path)
        entry = AuditEntry(
            action_name="action",
            verdict="approved",
            risk_score=0.2,
            risk_level="low",
        )
        audit.log_entry(entry)

        file_stat = log_path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        # Check that 'other' has no permissions
        assert (mode & stat.S_IROTH) == 0, "Audit file should not be world-readable"
        assert (mode & stat.S_IWOTH) == 0, "Audit file should not be world-writable"
        assert (mode & stat.S_IXOTH) == 0, "Audit file should not be world-executable"

    def test_audit_file_not_group_readable(self, tmp_path: Path):
        """The audit file must not be readable by group."""
        log_path = tmp_path / "audit_grp.jsonl"

        audit = AuditLogger(path=log_path)
        entry = AuditEntry(
            action_name="action",
            verdict="approved",
            risk_score=0.2,
            risk_level="low",
        )
        audit.log_entry(entry)

        file_stat = log_path.stat()
        mode = stat.S_IMODE(file_stat.st_mode)
        assert (mode & stat.S_IRGRP) == 0, "Audit file should not be group-readable"
        assert (mode & stat.S_IWGRP) == 0, "Audit file should not be group-writable"

    def test_parent_directories_created(self, tmp_path: Path):
        """Nested parent directories should be created for audit log path."""
        log_path = tmp_path / "deep" / "nested" / "dir" / "audit.jsonl"

        audit = AuditLogger(path=log_path)
        entry = AuditEntry(
            action_name="action",
            verdict="approved",
            risk_score=0.2,
            risk_level="low",
        )
        audit.log_entry(entry)

        assert log_path.exists()
        assert log_path.parent.exists()


# =========================================================================
# 9. Mode Validation (bonus security check)
# =========================================================================


class TestModeValidation:
    """Verify that invalid modes are rejected at construction time."""

    def test_invalid_mode_raises_value_error(self):
        """Attesta() with an unrecognised mode should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid mode"):
            Attesta(
                renderer=_ApproveAllRenderer(),
                mode="yolo",
            )

    def test_valid_modes_accepted(self):
        """All three valid modes should be accepted without error."""
        for mode in ("enforce", "shadow", "audit_only"):
            g = Attesta(renderer=_ApproveAllRenderer(), mode=mode)
            assert g._mode == mode
