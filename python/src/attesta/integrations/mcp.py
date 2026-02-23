"""Attesta integration for MCP (Model Context Protocol) servers.

Provides two patterns for enforcing human-in-the-loop approval on MCP tool
invocations, regardless of which client (VS Code, Cursor, Claude Code,
Windsurf, etc.) calls the tools.

* ``attesta_tool_handler`` -- a decorator for MCP ``call_tool`` handlers
  that evaluates each invocation with Attesta before execution.  Use this
  when you author your own MCP servers in Python.

* ``MCPProxy`` -- a stdio proxy that wraps ANY existing MCP server with
  Attesta approval, requiring **zero code changes** to the upstream server.
  Use this to enforce company-wide HITL policies across all MCP tools.

Architecture (proxy)::

    Editor / IDE  <--stdio-->  Attesta MCPProxy  <--stdio-->  Real MCP Server
                                    |
                                    +-- risk scoring per tool call
                                    +-- domain-aware evaluation (if profile registered)
                                    +-- policy enforcement (approve / deny / audit)
                                    +-- tamper-proof audit trail

Usage (decorator -- for Python MCP servers)::

    from mcp.server import Server
    from attesta import Attesta
    from attesta.integrations.mcp import attesta_tool_handler

    server = Server("my-server")
    attesta = Attesta.from_config("attesta.yaml")

    @server.call_tool()
    @attesta_tool_handler(attesta)
    async def call_tool(name: str, arguments: dict):
        ...  # Only executes if Attesta approves

Usage (proxy -- zero code changes, any MCP server)::

    # In your editor's MCP config, wrap the server command:
    attesta mcp wrap -- npx @modelcontextprotocol/server-filesystem /path

Install::

    pip install attesta
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from attesta.core.gate import TRUSTED_RISK_OVERRIDE_METADATA_KEY
from attesta.core.types import ActionContext, Verdict

if TYPE_CHECKING:
    from attesta import Attesta

__all__ = ["attesta_tool_handler", "MCPProxy"]

logger = logging.getLogger("attesta.integrations.mcp")


# ---------------------------------------------------------------------------
# Decorator for MCP call_tool handlers
# ---------------------------------------------------------------------------


def attesta_tool_handler(
    attesta: Attesta,
    *,
    risk_overrides: dict[str, str] | None = None,
) -> Callable[..., Any]:
    """Decorator that wraps an MCP ``call_tool`` handler with Attesta approval.

    Place this between ``@server.call_tool()`` and your handler function so
    that every tool invocation is evaluated for risk before execution::

        @server.call_tool()
        @attesta_tool_handler(attesta)
        async def call_tool(name: str, arguments: dict):
            ...

    Parameters
    ----------
    attesta:
        A configured :class:`~attesta.Attesta` instance.
    risk_overrides:
        Optional mapping of ``{tool_name: risk_level_str}`` that forces
        specific risk levels for named tools (e.g. ``{"rm_rf": "critical"}``).
    """
    overrides = risk_overrides or {}

    def decorator(handler: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(handler)
        async def wrapper(name: str, arguments: dict[str, Any] | None = None) -> Any:
            arguments = arguments or {}

            hints: dict[str, Any] = {}
            metadata: dict[str, Any] = {"source": "mcp"}
            if name in overrides:
                override = overrides[name]
                hints["risk_override"] = override
                metadata[TRUSTED_RISK_OVERRIDE_METADATA_KEY] = override

            ctx = ActionContext(
                function_name=name,
                kwargs=arguments,
                hints=hints,
                metadata=metadata,
            )

            result = await attesta.evaluate(ctx)

            if result.verdict in (Verdict.APPROVED, Verdict.MODIFIED):
                return await handler(name, arguments)

            risk_label = result.risk_assessment.level.value
            score = result.risk_assessment.score
            logger.info(
                "Attesta denied MCP tool %r (risk=%s, score=%.2f)",
                name,
                risk_label,
                score,
            )

            # Return an MCP-compatible error content block.
            try:
                from mcp.types import TextContent

                return [
                    TextContent(
                        type="text",
                        text=(f"Action denied by Attesta: {name} (risk: {risk_label}, score: {score:.2f})"),
                    )
                ]
            except ImportError:
                return [
                    {
                        "type": "text",
                        "text": (f"Action denied by Attesta: {name} (risk: {risk_label}, score: {score:.2f})"),
                    }
                ]

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# MCP Proxy
# ---------------------------------------------------------------------------


class MCPProxy:
    """Stdio proxy that wraps any MCP server with Attesta approval.

    Sits between the MCP client (editor / IDE) and the real MCP server,
    intercepting ``tools/call`` requests and evaluating them with Attesta
    before forwarding.  Denied tool calls never reach the upstream server --
    the proxy returns an error response directly.

    This is the recommended pattern for companies that want to enforce
    HITL policies across their entire MCP infrastructure without modifying
    any server code.

    Parameters
    ----------
    attesta:
        A configured :class:`~attesta.Attesta` instance.
    upstream_command:
        The command (and arguments) to start the upstream MCP server,
        e.g. ``["npx", "@modelcontextprotocol/server-filesystem", "/path"]``.
    risk_overrides:
        Optional mapping of ``{tool_name: risk_level_str}`` for explicit
        risk levels on specific tools.
    """

    def __init__(
        self,
        attesta: Attesta,
        upstream_command: list[str],
        *,
        risk_overrides: dict[str, str] | None = None,
    ) -> None:
        self.attesta = attesta
        self.upstream_command = upstream_command
        self.risk_overrides = risk_overrides or {}
        self._process: subprocess.Popen[bytes] | None = None
        self._stdout_lock = threading.Lock()

    def run(self) -> None:
        """Start the proxy.  Blocks until the upstream server exits or
        the client disconnects.
        """
        self._process = subprocess.Popen(
            self.upstream_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # upstream stderr passes through to terminal
        )

        _log_stderr(f"Attesta MCP proxy started, wrapping: {' '.join(self.upstream_command)}")

        # Background thread: forward upstream responses → client stdout.
        response_thread = threading.Thread(
            target=self._forward_responses,
            daemon=True,
        )
        response_thread.start()

        # Main thread: read client requests, evaluate, forward to upstream.
        try:
            self._process_requests()
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()

    # -- internal ----------------------------------------------------------

    def _process_requests(self) -> None:
        """Read JSON-RPC messages from our stdin (client) and process them."""
        assert self._process and self._process.stdin

        while True:
            msg = _decode_message(sys.stdin.buffer)
            if msg is None:
                break

            # Intercept tools/call requests.
            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                params = msg.get("params", {})
                tool_name = params.get("name", "unknown")
                arguments = params.get("arguments", {})

                approved, denial = self._evaluate(msg, tool_name, arguments)
                if not approved and denial is not None:
                    self._write_to_client(denial)
                    continue

            # Forward everything else to upstream.
            self._write_to_upstream(msg)

    def _forward_responses(self) -> None:
        """Read JSON-RPC messages from upstream stdout and forward to client."""
        assert self._process and self._process.stdout

        while self._process.poll() is None:
            msg = _decode_message(self._process.stdout)
            if msg is None:
                break
            self._write_to_client(msg)

    def _evaluate(
        self,
        request: dict[str, Any],
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[bool, dict[str, Any] | None]:
        """Evaluate a tool call with Attesta.

        Returns ``(should_forward, denial_response_or_none)``.
        """
        hints: dict[str, Any] = {}
        metadata: dict[str, Any] = {"source": "mcp_proxy"}
        if tool_name in self.risk_overrides:
            override = self.risk_overrides[tool_name]
            hints["risk_override"] = override
            metadata[TRUSTED_RISK_OVERRIDE_METADATA_KEY] = override

        ctx = ActionContext(
            function_name=tool_name,
            kwargs=arguments,
            hints=hints,
            metadata=metadata,
        )

        # Run the async evaluate in a one-shot event loop.
        result = asyncio.run(self.attesta.evaluate(ctx))

        if result.verdict in (Verdict.APPROVED, Verdict.MODIFIED):
            _log_stderr(
                f"  [approved] {tool_name} "
                f"(risk: {result.risk_assessment.level.value}, "
                f"score: {result.risk_assessment.score:.2f})"
            )
            return True, None

        risk_label = result.risk_assessment.level.value
        score = result.risk_assessment.score
        _log_stderr(f"  [DENIED]   {tool_name} (risk: {risk_label}, score: {score:.2f})")

        denial = {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"Action denied by Attesta: {tool_name} "
                            f"(risk: {risk_label}, score: {score:.2f}). "
                            f"This action requires human approval that was "
                            f"not granted."
                        ),
                    }
                ],
                "isError": True,
            },
        }

        return False, denial

    def _write_to_client(self, msg: dict[str, Any]) -> None:
        """Write a JSON-RPC message to our stdout (→ client)."""
        data = _encode_message(msg)
        with self._stdout_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    def _write_to_upstream(self, msg: dict[str, Any]) -> None:
        """Write a JSON-RPC message to upstream stdin."""
        assert self._process and self._process.stdin
        data = _encode_message(msg)
        self._process.stdin.write(data)
        self._process.stdin.flush()


# ---------------------------------------------------------------------------
# MCP stdio protocol helpers
# ---------------------------------------------------------------------------


def _decode_message(stream: Any) -> dict[str, Any] | None:
    """Read one JSON-RPC message from an MCP stdio stream.

    Auto-detects the framing format:

    * **Content-Length framing** (official MCP spec) -- messages are preceded
      by ``Content-Length: <N>\\r\\n\\r\\n`` headers.
    * **Newline-delimited JSON** (used by some implementations) -- each
      message is a single JSON object on its own line.
    """
    while True:
        try:
            raw = stream.readline()
        except (OSError, ValueError):
            return None

        if not raw:
            return None

        text = (raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else raw).strip()

        if not text:
            continue

        # Content-Length framing (official MCP / LSP style).
        if text.lower().startswith("content-length:"):
            try:
                length = int(text.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                continue

            # Skip remaining headers until the blank line.
            while True:
                header_raw = stream.readline()
                header_text = (
                    header_raw.decode("utf-8", errors="replace")
                    if isinstance(header_raw, (bytes, bytearray))
                    else header_raw
                ).strip()
                if not header_text:
                    break

            # Read the body.
            body_raw = stream.read(length)
            if not body_raw:
                return None
            # Verify we got the full body (short read = truncated stream).
            actual_len = len(body_raw)
            if actual_len < length:
                return None
            if isinstance(body_raw, (bytes, bytearray)):
                body_raw = body_raw.decode("utf-8", errors="replace")
            try:
                result: dict[str, Any] = json.loads(body_raw)
                return result
            except json.JSONDecodeError:
                return None

        # Newline-delimited JSON fallback.
        if text.startswith("{"):
            try:
                result = json.loads(text)
                return result
            except json.JSONDecodeError:
                continue

        # Unknown line -- skip and try the next one.


def _encode_message(msg: dict[str, Any]) -> bytes:
    """Encode a JSON-RPC message with Content-Length framing."""
    body = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    return header + body


def _log_stderr(message: str) -> None:
    """Log a message to stderr (visible in the terminal, not to MCP client)."""
    print(f"[attesta] {message}", file=sys.stderr, flush=True)
