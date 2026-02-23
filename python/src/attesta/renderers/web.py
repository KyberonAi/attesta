"""Browser-based challenge renderer using a local HTTP server.

Zero external dependencies -- uses :mod:`http.server` from stdlib.

The :class:`WebRenderer` starts a lightweight HTTP server in a background
thread, serves an HTML page for each challenge type, and waits for the
operator's response via form submission.

Usage::

    from attesta import Attesta
    from attesta.renderers.web import WebRenderer

    attesta = Attesta(renderer=WebRenderer())
"""

from __future__ import annotations

import asyncio
import html as _html
import logging
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs

from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    Verdict,
)

__all__ = ["WebRenderer"]

logger = logging.getLogger("attesta.renderers.web")


def _esc(s: object) -> str:
    """HTML-escape a value for safe interpolation into templates."""
    return _html.escape(str(s), quote=True)


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_CSS = """
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 700px;
    margin: 40px auto;
    padding: 0 20px;
    background: #f8faf8;
    color: #1a1a1a;
}
h1 { color: #2d7a3a; border-bottom: 2px solid #2d7a3a; padding-bottom: 8px; }
.risk-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    font-weight: bold;
    color: white;
    font-size: 14px;
}
.risk-low { background: #2d7a3a; }
.risk-medium { background: #d4a017; }
.risk-high { background: #d45317; }
.risk-critical { background: #c0392b; }
.detail { margin: 12px 0; padding: 12px; background: white; border-radius: 6px; border: 1px solid #e0e0e0; }
.detail label { font-weight: bold; color: #555; }
.factors { font-size: 13px; color: #666; }
textarea { width: 100%; min-height: 120px; font-size: 15px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
.btn {
    padding: 10px 28px;
    font-size: 16px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    margin-right: 10px;
    color: white;
}
.btn-approve { background: #2d7a3a; }
.btn-approve:disabled { background: #a0c4a7; cursor: not-allowed; }
.btn-deny { background: #c0392b; }
.countdown { color: #888; font-size: 13px; margin-top: 8px; }
.quiz-option { display: block; margin: 6px 0; font-size: 15px; }
"""

_RISK_CLASS = {
    "low": "risk-low",
    "medium": "risk-medium",
    "high": "risk-high",
    "critical": "risk-critical",
}


def _risk_badge(level: str) -> str:
    cls = _RISK_CLASS.get(level, "risk-medium")
    return f'<span class="risk-badge {cls}">{_esc(level.upper())}</span>'


def _base_html(title: str, body: str, min_review_seconds: float = 0) -> str:
    countdown_js = ""
    if min_review_seconds > 0:
        countdown_js = f"""
<script>
(function() {{
    var remaining = {int(min_review_seconds)};
    var btn = document.getElementById('submit-btn');
    var countdown = document.getElementById('countdown');
    if (btn) btn.disabled = true;
    var iv = setInterval(function() {{
        remaining--;
        if (countdown) countdown.textContent = 'Submit available in ' + remaining + 's...';
        if (remaining <= 0) {{
            clearInterval(iv);
            if (btn) btn.disabled = false;
            if (countdown) countdown.textContent = '';
        }}
    }}, 1000);
}})();
</script>
"""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{_CSS}</style></head>
<body>{body}{countdown_js}</body></html>"""


def _confirm_page(ctx: ActionContext, risk: RiskAssessment) -> str:
    factors = ""
    if risk.factors:
        items = "".join(f"<li>{_esc(f.name)}: {_esc(f.description)}</li>" for f in risk.factors)
        factors = f'<div class="factors"><strong>Risk factors:</strong><ul>{items}</ul></div>'

    body = f"""
<h1>Attesta -- Approval Required</h1>
<div class="detail">
    <label>Action:</label> {_esc(ctx.function_name)}<br>
    <label>Call:</label> {_esc(ctx.description)}<br>
    <label>Risk:</label> {_risk_badge(risk.level.value)} ({risk.score:.2f})
    {factors}
</div>
<form method="POST" action="/respond">
    <button class="btn btn-approve" type="submit" name="verdict" value="approve" id="submit-btn">Approve</button>
    <button class="btn btn-deny" type="submit" name="verdict" value="deny">Deny</button>
</form>
<div class="countdown" id="countdown"></div>
"""
    return _base_html("Attesta - Confirm", body)


def _quiz_page(ctx: ActionContext, risk: RiskAssessment) -> str:
    body = f"""
<h1>Attesta -- Quiz Challenge</h1>
<div class="detail">
    <label>Action:</label> {_esc(ctx.function_name)}<br>
    <label>Risk:</label> {_risk_badge(risk.level.value)} ({risk.score:.2f})
</div>
<form method="POST" action="/respond">
    <p><strong>What will this action do?</strong></p>
    <label class="quiz-option"><input type="radio" name="answer" value="approve"> I understand and approve</label>
    <label class="quiz-option"><input type="radio" name="answer" value="deny"> I do not understand or deny</label>
    <br>
    <button class="btn btn-approve" type="submit" id="submit-btn">Submit</button>
</form>
<div class="countdown" id="countdown"></div>
"""
    return _base_html("Attesta - Quiz", body)


def _teach_back_page(ctx: ActionContext, risk: RiskAssessment, min_review: float) -> str:
    factors = ""
    if risk.factors:
        items = "".join(f"<li>{_esc(f.name)}: {_esc(f.description)}</li>" for f in risk.factors)
        factors = f'<div class="factors"><strong>Risk factors:</strong><ul>{items}</ul></div>'

    body = f"""
<h1>Attesta -- Teach-Back Challenge</h1>
<div class="detail">
    <label>Action:</label> {_esc(ctx.function_name)}<br>
    <label>Call:</label> {_esc(ctx.description)}<br>
    <label>Risk:</label> {_risk_badge(risk.level.value)} ({risk.score:.2f})<br>
    {"<label>Docs:</label> " + _esc(ctx.function_doc) + "<br>" if ctx.function_doc else ""}
    {factors}
</div>
<form method="POST" action="/respond">
    <p><strong>In your own words, explain what this action will do and its effects:</strong></p>
    <textarea name="explanation" placeholder="Type your explanation here..." required></textarea><br><br>
    <button class="btn btn-approve" type="submit" id="submit-btn">Submit Explanation</button>
</form>
<div class="countdown" id="countdown"></div>
"""
    return _base_html("Attesta - Teach-Back", body, min_review)


def _result_page(passed: bool) -> str:
    status = "APPROVED" if passed else "DENIED"
    color = "#2d7a3a" if passed else "#c0392b"
    body = f"""
<h1 style="color: {color}">Challenge Result: {status}</h1>
<p>You may close this tab. The pipeline has been notified.</p>
"""
    return _base_html(f"Attesta - {status}", body)


# ---------------------------------------------------------------------------
# WebRenderer
# ---------------------------------------------------------------------------


class WebRenderer:
    """Browser-based renderer using a local HTTP server.

    Parameters
    ----------
    host:
        Bind address. Default ``"127.0.0.1"`` (localhost only).
    port:
        TCP port. Default ``8910``.
    auto_open:
        Whether to auto-open the browser. Default ``True``.
    min_review_seconds:
        Minimum time (s) before submit becomes active. Default ``0``.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8910,
        auto_open: bool = True,
        min_review_seconds: float = 0,
    ) -> None:
        self.host = host
        self.port = port
        self.auto_open = auto_open
        self.min_review_seconds = min_review_seconds
        self._csrf_token: str = ""

    async def render_approval(self, ctx: ActionContext, risk: RiskAssessment) -> Verdict:
        html = _confirm_page(ctx, risk)
        response = await self._serve_and_wait(html)
        verdict_str = response.get("verdict", ["deny"])[0]
        return Verdict.APPROVED if verdict_str == "approve" else Verdict.DENIED

    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        start = time.monotonic()

        if challenge_type == ChallengeType.MULTI_PARTY:
            # Fail closed: this renderer is single-session and cannot reliably
            # enforce independent multi-party approvals.
            logger.warning(
                "WebRenderer does not support multi-party approval. Denying %s by default.",
                ctx.function_name,
            )
            return ChallengeResult(
                passed=False,
                challenge_type=challenge_type,
                response_time_seconds=round(time.monotonic() - start, 3),
                questions_asked=0,
                questions_correct=0,
                details={
                    "source": "web",
                    "reason": (
                        "multi-party challenge is unsupported by WebRenderer; "
                        "configure a renderer that supports independent approvers"
                    ),
                },
            )

        if challenge_type == ChallengeType.TEACH_BACK:
            html = _teach_back_page(ctx, risk, self.min_review_seconds)
        elif challenge_type == ChallengeType.QUIZ:
            html = _quiz_page(ctx, risk)
        else:
            html = _confirm_page(ctx, risk)

        response = await self._serve_and_wait(html)
        elapsed = time.monotonic() - start

        # Enforce minimum review time server-side
        if elapsed < self.min_review_seconds:
            await asyncio.sleep(self.min_review_seconds - elapsed)
            elapsed = time.monotonic() - start

        # Parse response
        if challenge_type == ChallengeType.TEACH_BACK:
            explanation = response.get("explanation", [""])[0]
            passed = len(explanation.split()) >= 5  # Basic check
            return ChallengeResult(
                passed=passed,
                challenge_type=challenge_type,
                response_time_seconds=elapsed,
                questions_asked=1,
                questions_correct=1 if passed else 0,
                details={"explanation": explanation, "source": "web"},
            )
        elif challenge_type == ChallengeType.QUIZ:
            answer = response.get("answer", ["deny"])[0]
            passed = answer == "approve"
        else:
            verdict_str = response.get("verdict", ["deny"])[0]
            passed = verdict_str == "approve"

        return ChallengeResult(
            passed=passed,
            challenge_type=challenge_type,
            response_time_seconds=elapsed,
            questions_asked=1,
            questions_correct=1 if passed else 0,
            details={"source": "web"},
        )

    async def render_info(self, message: str) -> None:
        logger.info("[web-renderer] %s", message)

    async def render_auto_approved(self, ctx: ActionContext, risk: RiskAssessment) -> None:
        logger.debug(
            "[web-renderer] Auto-approved %s (risk=%.2f)",
            ctx.function_name,
            risk.score,
        )

    # -- internal ---------------------------------------------------------

    async def _serve_and_wait(self, html: str) -> dict[str, list[str]]:
        """Start server, open browser, wait for form submission, return data."""
        result: dict[str, list[str]] = {}
        event = threading.Event()

        self._csrf_token = secrets.token_urlsafe(32)
        csrf_token = self._csrf_token

        # Inject CSRF token into all forms
        html = html.replace(
            '<form method="POST" action="/respond">',
            f'<form method="POST" action="/respond"><input type="hidden" name="_csrf" value="{csrf_token}">',
        )

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self_handler: Handler) -> None:  # noqa: N805
                self_handler.send_response(200)
                self_handler.send_header("Content-Type", "text/html; charset=utf-8")
                self_handler.end_headers()
                self_handler.wfile.write(html.encode("utf-8"))

            def do_POST(self_handler: Handler) -> None:  # noqa: N805
                nonlocal result
                length = int(self_handler.headers.get("Content-Length", 0))
                if length > 65536:  # 64KB limit
                    self_handler.send_response(413)
                    self_handler.send_header("Content-Type", "text/plain")
                    self_handler.end_headers()
                    self_handler.wfile.write(b"Request body too large")
                    return
                body = self_handler.rfile.read(length).decode("utf-8")
                result = parse_qs(body)

                # Validate CSRF token
                submitted_csrf = result.get("_csrf", [""])[0]
                if submitted_csrf != csrf_token:
                    self_handler.send_response(403)
                    self_handler.send_header("Content-Type", "text/plain")
                    self_handler.end_headers()
                    self_handler.wfile.write(b"CSRF token invalid")
                    return

                # Send result page
                passed = result.get("verdict", [""])[0] == "approve" or bool(result.get("explanation"))
                resp_html = _result_page(passed)
                self_handler.send_response(200)
                self_handler.send_header("Content-Type", "text/html; charset=utf-8")
                self_handler.end_headers()
                self_handler.wfile.write(resp_html.encode("utf-8"))
                event.set()

            def log_message(self_handler: Handler, format: str, *args: Any) -> None:  # noqa: N805
                pass  # Suppress HTTP logs

        server = HTTPServer((self.host, self.port), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        url = f"http://{self.host}:{self.port}"
        logger.info("Attesta web challenge at %s", url)

        if self.auto_open:
            try:
                webbrowser.open(url)
            except Exception:
                pass

        # Wait for response without blocking the event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: event.wait(timeout=600))
        server.shutdown()

        return result
