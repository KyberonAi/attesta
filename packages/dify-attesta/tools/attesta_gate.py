"""Attesta Approval tool for Dify."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import threading
from typing import Any, Generator

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from attesta.core.gate import Attesta
from attesta.core.types import ActionContext, RiskLevel, Verdict


def _run_coroutine_in_worker_thread(
    coro_factory: Any,
    *,
    timeout: float | None = None,
) -> Any:
    """Run a coroutine in a dedicated thread to avoid loop-thread deadlocks."""
    result_future: concurrent.futures.Future[Any] = concurrent.futures.Future()

    def _runner() -> None:
        try:
            result = asyncio.run(coro_factory())
        except Exception as exc:
            result_future.set_exception(exc)
        else:
            result_future.set_result(result)

    thread = threading.Thread(
        target=_runner,
        name="attesta-dify-sync-bridge",
        daemon=True,
    )
    thread.start()
    return result_future.result(timeout=timeout)


class AttestaGateTool(Tool):
    """Evaluates AI agent actions for risk using the Attesta framework."""

    def _invoke(
        self,
        tool_parameters: dict[str, Any],
    ) -> Generator[ToolInvokeMessage, None, None]:
        """Evaluate an action through Attesta.

        Yields a JSON message with the verdict, risk score, and audit info.
        """
        function_name = tool_parameters.get("function_name", "unknown_action")
        risk_level_str = tool_parameters.get("risk_level", "auto")
        action_args_raw = tool_parameters.get("action_args", "{}")

        # Parse action arguments
        action_args: dict[str, Any] = {}
        if isinstance(action_args_raw, str):
            try:
                action_args = json.loads(action_args_raw)
            except (json.JSONDecodeError, TypeError):
                action_args = {"raw_input": action_args_raw}
        elif isinstance(action_args_raw, dict):
            action_args = action_args_raw

        # Determine risk override
        risk_override: RiskLevel | None = None
        if risk_level_str and risk_level_str != "auto":
            try:
                risk_override = RiskLevel(risk_level_str)
            except ValueError:
                pass

        # Get risk threshold from credentials
        risk_hints: dict[str, Any] = {}
        threshold = self.runtime.credentials.get("risk_threshold")
        if threshold is not None:
            risk_hints["threshold"] = float(threshold)

        # Build attesta instance
        attesta = Attesta(
            risk_override=risk_override,
            risk_hints=risk_hints,
        )

        # Build action context
        ctx = ActionContext(
            function_name=function_name,
            kwargs=action_args,
            hints=risk_hints,
            environment="production",
            metadata={"source": "dify"},
        )

        # Run async evaluation
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            result = _run_coroutine_in_worker_thread(
                lambda: attesta.evaluate(ctx),
                timeout=30,
            )
        else:
            result = asyncio.run(attesta.evaluate(ctx))

        denied = result.verdict in (
            Verdict.DENIED,
            Verdict.TIMED_OUT,
            Verdict.ESCALATED,
        )

        yield self.create_json_message({
            "verdict": result.verdict.value,
            "risk_score": result.risk_assessment.score,
            "risk_level": result.risk_assessment.level.value,
            "denied": denied,
            "audit_entry_id": result.audit_entry_id,
            "function_name": function_name,
            "message": (
                f"Action '{function_name}' was {'denied' if denied else 'approved'} "
                f"(risk: {result.risk_assessment.level.value}, "
                f"score: {result.risk_assessment.score:.2f})"
            ),
        })
