"""Tests for attesta.integrations.mcp -- MCP tool handler and proxy."""

from __future__ import annotations

import io
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from attesta.core.types import (
    ActionContext,
    ApprovalResult,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    RiskLevel,
    Verdict,
)
from attesta.integrations.mcp import (
    MCPProxy,
    _decode_message,
    _encode_message,
    attesta_tool_handler,
)


# =========================================================================
# Helpers
# =========================================================================

def _make_approval(
    verdict: Verdict = Verdict.APPROVED,
    risk_level: RiskLevel = RiskLevel.LOW,
    score: float = 0.1,
) -> ApprovalResult:
    """Build a minimal ApprovalResult for testing."""
    return ApprovalResult(
        verdict=verdict,
        risk_assessment=RiskAssessment(score=score, level=risk_level),
    )


def _make_mock_attesta(
    verdict: Verdict = Verdict.APPROVED,
    risk_level: RiskLevel = RiskLevel.LOW,
    score: float = 0.1,
) -> MagicMock:
    """Create a mock Attesta instance that returns a fixed result."""
    mock = MagicMock()
    result = _make_approval(verdict=verdict, risk_level=risk_level, score=score)
    mock.evaluate = AsyncMock(return_value=result)
    return mock


# =========================================================================
# _encode_message / _decode_message -- protocol helpers
# =========================================================================

class TestEncodeMessage:
    def test_produces_content_length_framing(self):
        msg = {"jsonrpc": "2.0", "method": "ping", "id": 1}
        data = _encode_message(msg)

        assert data.startswith(b"Content-Length: ")
        assert b"\r\n\r\n" in data

        # Split header from body.
        header, body = data.split(b"\r\n\r\n", 1)
        length = int(header.split(b": ")[1])
        assert length == len(body)

        parsed = json.loads(body)
        assert parsed == msg

    def test_utf8_body(self):
        msg = {"text": "hello \u00e9"}
        data = _encode_message(msg)
        body = data.split(b"\r\n\r\n", 1)[1]
        assert json.loads(body)["text"] == "hello \u00e9"


class TestDecodeMessage:
    def test_content_length_framing(self):
        """Reads a message with standard Content-Length framing."""
        msg = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        body = json.dumps(msg).encode("utf-8")
        raw = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8") + body

        stream = io.BytesIO(raw)
        decoded = _decode_message(stream)
        assert decoded == msg

    def test_newline_delimited_json(self):
        """Reads a message as newline-delimited JSON."""
        msg = {"jsonrpc": "2.0", "method": "initialize", "id": 1}
        raw = json.dumps(msg).encode("utf-8") + b"\n"

        stream = io.BytesIO(raw)
        decoded = _decode_message(stream)
        assert decoded == msg

    def test_empty_stream_returns_none(self):
        stream = io.BytesIO(b"")
        assert _decode_message(stream) is None

    def test_skips_blank_lines(self):
        """Blank lines before the message are skipped."""
        msg = {"jsonrpc": "2.0", "id": 2}
        raw = b"\n\n" + json.dumps(msg).encode("utf-8") + b"\n"

        stream = io.BytesIO(raw)
        decoded = _decode_message(stream)
        assert decoded == msg

    def test_content_length_with_extra_headers(self):
        """Handles extra headers between Content-Length and body."""
        msg = {"method": "test"}
        body = json.dumps(msg).encode("utf-8")
        raw = (
            f"Content-Length: {len(body)}\r\n".encode("utf-8")
            + b"Content-Type: application/json\r\n"
            + b"\r\n"
            + body
        )
        stream = io.BytesIO(raw)
        decoded = _decode_message(stream)
        assert decoded == msg

    def test_skips_invalid_json_lines(self):
        """Invalid JSON lines are skipped, next valid message is returned."""
        msg = {"jsonrpc": "2.0", "id": 99}
        raw = b"not json\n" + json.dumps(msg).encode("utf-8") + b"\n"

        stream = io.BytesIO(raw)
        decoded = _decode_message(stream)
        assert decoded == msg

    def test_roundtrip(self):
        """Encode then decode produces the original message."""
        msg = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "deploy"}, "id": 42}
        encoded = _encode_message(msg)
        stream = io.BytesIO(encoded)
        decoded = _decode_message(stream)
        assert decoded == msg


# =========================================================================
# attesta_tool_handler -- decorator
# =========================================================================

class TestAttestaToolHandler:
    async def test_approved_calls_through(self):
        """When Attesta approves, the original handler executes."""
        mock_attesta = _make_mock_attesta(verdict=Verdict.APPROVED)

        @attesta_tool_handler(mock_attesta)
        async def call_tool(name: str, arguments: dict):
            return [{"type": "text", "text": f"executed {name}"}]

        result = await call_tool("list_files", {"path": "/tmp"})

        assert result == [{"type": "text", "text": "executed list_files"}]
        mock_attesta.evaluate.assert_awaited_once()

        # Verify the ActionContext was built correctly.
        ctx = mock_attesta.evaluate.call_args[0][0]
        assert ctx.function_name == "list_files"
        assert ctx.kwargs == {"path": "/tmp"}
        assert ctx.metadata == {"source": "mcp"}

    async def test_denied_returns_denial_message(self):
        """When Attesta denies, a denial message is returned instead."""
        mock_attesta = _make_mock_attesta(
            verdict=Verdict.DENIED, risk_level=RiskLevel.CRITICAL, score=0.92,
        )

        handler_called = False

        @attesta_tool_handler(mock_attesta)
        async def call_tool(name: str, arguments: dict):
            nonlocal handler_called
            handler_called = True
            return [{"type": "text", "text": "should not reach"}]

        result = await call_tool("drop_database", {"db": "production"})

        assert handler_called is False
        assert len(result) == 1
        assert "denied" in result[0]["text"].lower()
        assert "drop_database" in result[0]["text"]
        assert "critical" in result[0]["text"]

    async def test_risk_overrides_applied(self):
        """Risk overrides are passed as hints to Attesta."""
        mock_attesta = _make_mock_attesta(verdict=Verdict.APPROVED)

        @attesta_tool_handler(mock_attesta, risk_overrides={"rm_rf": "critical"})
        async def call_tool(name: str, arguments: dict):
            return [{"type": "text", "text": "ok"}]

        await call_tool("rm_rf", {})

        ctx = mock_attesta.evaluate.call_args[0][0]
        assert ctx.hints.get("risk_override") == "critical"

    async def test_no_risk_override_for_unlisted_tool(self):
        """Tools not in risk_overrides have no risk_override hint."""
        mock_attesta = _make_mock_attesta(verdict=Verdict.APPROVED)

        @attesta_tool_handler(mock_attesta, risk_overrides={"rm_rf": "critical"})
        async def call_tool(name: str, arguments: dict):
            return [{"type": "text", "text": "ok"}]

        await call_tool("list_files", {})

        ctx = mock_attesta.evaluate.call_args[0][0]
        assert "risk_override" not in ctx.hints

    async def test_none_arguments_defaults_to_empty_dict(self):
        """When arguments is None, it should default to {}."""
        mock_attesta = _make_mock_attesta(verdict=Verdict.APPROVED)

        @attesta_tool_handler(mock_attesta)
        async def call_tool(name: str, arguments: dict):
            return [{"type": "text", "text": f"args={arguments}"}]

        result = await call_tool("ping", None)
        assert result == [{"type": "text", "text": "args={}"}]

    async def test_modified_verdict_calls_through(self):
        """MODIFIED verdict should still call the original handler."""
        mock_attesta = _make_mock_attesta(verdict=Verdict.MODIFIED)

        @attesta_tool_handler(mock_attesta)
        async def call_tool(name: str, arguments: dict):
            return [{"type": "text", "text": "executed"}]

        result = await call_tool("update_file", {"path": "a.txt"})
        assert result == [{"type": "text", "text": "executed"}]

    async def test_timed_out_verdict_returns_denial(self):
        """TIMED_OUT verdict is treated as a denial."""
        mock_attesta = _make_mock_attesta(
            verdict=Verdict.TIMED_OUT, risk_level=RiskLevel.HIGH, score=0.75,
        )

        @attesta_tool_handler(mock_attesta)
        async def call_tool(name: str, arguments: dict):
            return [{"type": "text", "text": "should not reach"}]

        result = await call_tool("deploy", {})
        assert "denied" in result[0]["text"].lower()


# =========================================================================
# MCPProxy._evaluate -- evaluation logic
# =========================================================================

class TestMCPProxyEvaluate:
    def _make_proxy(
        self,
        verdict: Verdict = Verdict.APPROVED,
        risk_level: RiskLevel = RiskLevel.LOW,
        score: float = 0.1,
        risk_overrides: dict[str, str] | None = None,
    ) -> MCPProxy:
        mock_attesta = _make_mock_attesta(
            verdict=verdict, risk_level=risk_level, score=score,
        )
        return MCPProxy(
            attesta=mock_attesta,
            upstream_command=["echo", "test"],
            risk_overrides=risk_overrides,
        )

    def test_approved_returns_true_none(self):
        proxy = self._make_proxy(verdict=Verdict.APPROVED)
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}

        approved, denial = proxy._evaluate(request, "list_files", {"path": "/"})

        assert approved is True
        assert denial is None

    def test_denied_returns_false_with_response(self):
        proxy = self._make_proxy(
            verdict=Verdict.DENIED, risk_level=RiskLevel.CRITICAL, score=0.95,
        )
        request = {"jsonrpc": "2.0", "id": 42, "method": "tools/call"}

        approved, denial = proxy._evaluate(request, "drop_db", {})

        assert approved is False
        assert denial is not None

        # Verify JSON-RPC response structure.
        assert denial["jsonrpc"] == "2.0"
        assert denial["id"] == 42
        assert denial["result"]["isError"] is True
        assert len(denial["result"]["content"]) == 1
        assert "drop_db" in denial["result"]["content"][0]["text"]
        assert "critical" in denial["result"]["content"][0]["text"]

    def test_modified_verdict_approved(self):
        proxy = self._make_proxy(verdict=Verdict.MODIFIED)
        request = {"jsonrpc": "2.0", "id": 3}

        approved, denial = proxy._evaluate(request, "update", {})

        assert approved is True
        assert denial is None

    def test_risk_overrides_passed_as_hints(self):
        proxy = self._make_proxy(
            verdict=Verdict.APPROVED,
            risk_overrides={"dangerous_tool": "critical"},
        )
        request = {"jsonrpc": "2.0", "id": 1}

        proxy._evaluate(request, "dangerous_tool", {"arg": "val"})

        ctx = proxy.attesta.evaluate.call_args[0][0]
        assert ctx.hints.get("risk_override") == "critical"
        assert ctx.function_name == "dangerous_tool"
        assert ctx.kwargs == {"arg": "val"}
        assert ctx.metadata == {"source": "mcp_proxy"}

    def test_denial_preserves_request_id(self):
        """The denial response must carry the same id as the request."""
        proxy = self._make_proxy(
            verdict=Verdict.DENIED, risk_level=RiskLevel.HIGH, score=0.8,
        )

        for req_id in [1, 99, "abc-123", None]:
            request = {"jsonrpc": "2.0", "id": req_id}
            _, denial = proxy._evaluate(request, "tool", {})
            assert denial["id"] == req_id

    def test_escalated_verdict_is_denied(self):
        """ESCALATED verdict should be treated as denial."""
        proxy = self._make_proxy(
            verdict=Verdict.ESCALATED, risk_level=RiskLevel.CRITICAL, score=0.9,
        )
        request = {"jsonrpc": "2.0", "id": 5}

        approved, denial = proxy._evaluate(request, "nuke", {})

        assert approved is False
        assert denial is not None
        assert denial["result"]["isError"] is True


# =========================================================================
# MCPProxy -- request routing
# =========================================================================

class TestMCPProxyRouting:
    """Test that the proxy correctly routes messages based on method."""

    def test_tools_call_is_intercepted(self):
        """A tools/call message triggers evaluation."""
        proxy = MCPProxy(
            attesta=_make_mock_attesta(verdict=Verdict.APPROVED),
            upstream_command=["echo"],
        )

        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/a"}},
        }

        # The message is a tools/call, so _evaluate should be invoked.
        assert msg.get("method") == "tools/call"
        params = msg.get("params", {})
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})

        approved, _ = proxy._evaluate(msg, tool_name, arguments)
        assert approved is True

        ctx = proxy.attesta.evaluate.call_args[0][0]
        assert ctx.function_name == "read_file"
        assert ctx.kwargs == {"path": "/tmp/a"}

    def test_non_tools_call_not_intercepted(self):
        """Messages that are not tools/call should not trigger evaluation."""
        messages = [
            {"jsonrpc": "2.0", "method": "initialize", "id": 1},
            {"jsonrpc": "2.0", "method": "tools/list", "id": 2},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 3, "result": {"tools": []}},
        ]

        for msg in messages:
            # These should NOT match the tools/call interception condition.
            assert msg.get("method") != "tools/call"


# =========================================================================
# MCPProxy -- write helpers
# =========================================================================

class TestMCPProxyWrite:
    def test_write_to_client(self):
        """_write_to_client writes Content-Length framed message to stdout."""
        proxy = MCPProxy(
            attesta=_make_mock_attesta(),
            upstream_command=["echo"],
        )

        msg = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        buf = io.BytesIO()

        with patch("sys.stdout") as mock_stdout:
            mock_stdout.buffer = buf
            proxy._write_to_client(msg)

        written = buf.getvalue()
        assert written.startswith(b"Content-Length: ")
        body = written.split(b"\r\n\r\n", 1)[1]
        assert json.loads(body) == msg

    def test_write_to_upstream(self):
        """_write_to_upstream writes to the subprocess stdin."""
        proxy = MCPProxy(
            attesta=_make_mock_attesta(),
            upstream_command=["echo"],
        )

        mock_process = MagicMock()
        mock_stdin = io.BytesIO()
        mock_process.stdin = mock_stdin
        proxy._process = mock_process

        msg = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        proxy._write_to_upstream(msg)

        written = mock_stdin.getvalue()
        assert written.startswith(b"Content-Length: ")
        body = written.split(b"\r\n\r\n", 1)[1]
        assert json.loads(body) == msg
