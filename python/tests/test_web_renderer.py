"""Tests for attesta.renderers.web -- WebRenderer."""

from __future__ import annotations

import asyncio
import threading
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from attesta.core.types import (
    ActionContext,
    ChallengeType,
    RiskAssessment,
    RiskLevel,
    Verdict,
)
from attesta.renderers.web import WebRenderer


def _find_free_port() -> int:
    """Find a free TCP port."""
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestWebRenderer:
    async def test_confirm_approve(self):
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="deploy_service", args=("web",))
        risk = RiskAssessment(score=0.45, level=RiskLevel.MEDIUM)

        # Submit approval in a background thread after a brief delay
        def submit():
            time.sleep(0.5)
            data = urlencode({"verdict": "approve"}).encode()
            req = Request(f"http://127.0.0.1:{port}/respond", data=data, method="POST")
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert verdict == Verdict.APPROVED

    async def test_confirm_deny(self):
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="delete_all")
        risk = RiskAssessment(score=0.7, level=RiskLevel.HIGH)

        def submit():
            time.sleep(0.5)
            data = urlencode({"verdict": "deny"}).encode()
            req = Request(f"http://127.0.0.1:{port}/respond", data=data, method="POST")
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        verdict = await renderer.render_approval(ctx, risk)
        assert verdict == Verdict.DENIED

    async def test_challenge_confirm(self):
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="restart_service")
        risk = RiskAssessment(score=0.5, level=RiskLevel.MEDIUM)

        def submit():
            time.sleep(0.5)
            data = urlencode({"verdict": "approve"}).encode()
            req = Request(f"http://127.0.0.1:{port}/respond", data=data, method="POST")
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        result = await renderer.render_challenge(ctx, risk, ChallengeType.CONFIRM)
        assert result.passed is True
        assert result.challenge_type is ChallengeType.CONFIRM

    async def test_teach_back_challenge(self):
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="drop_database", args=("users",))
        risk = RiskAssessment(score=0.9, level=RiskLevel.CRITICAL)

        def submit():
            time.sleep(0.5)
            data = urlencode({
                "explanation": "This will permanently drop the users database table and all its data"
            }).encode()
            req = Request(f"http://127.0.0.1:{port}/respond", data=data, method="POST")
            urlopen(req, timeout=5)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()

        result = await renderer.render_challenge(ctx, risk, ChallengeType.TEACH_BACK)
        assert result.passed is True
        assert result.details.get("source") == "web"

    async def test_serves_html(self):
        port = _find_free_port()
        renderer = WebRenderer(port=port, auto_open=False)
        ctx = ActionContext(function_name="test_fn")
        risk = RiskAssessment(score=0.3, level=RiskLevel.MEDIUM)

        html_received = []

        def fetch_and_submit():
            time.sleep(0.3)
            # GET the page first
            resp = urlopen(f"http://127.0.0.1:{port}", timeout=5)
            html_received.append(resp.read().decode("utf-8"))
            # Then submit
            time.sleep(0.2)
            data = urlencode({"verdict": "approve"}).encode()
            req = Request(f"http://127.0.0.1:{port}/respond", data=data, method="POST")
            urlopen(req, timeout=5)

        thread = threading.Thread(target=fetch_and_submit, daemon=True)
        thread.start()

        await renderer.render_approval(ctx, risk)
        assert len(html_received) == 1
        assert "Attesta" in html_received[0]
        assert "test_fn" in html_received[0]

    async def test_auto_approved_is_noop(self):
        renderer = WebRenderer(auto_open=False)
        ctx = ActionContext(function_name="safe_fn")
        risk = RiskAssessment(score=0.1, level=RiskLevel.LOW)
        # Should not start a server or block
        await renderer.render_auto_approved(ctx, risk)

    async def test_render_info_is_noop(self):
        renderer = WebRenderer(auto_open=False)
        await renderer.render_info("test message")
