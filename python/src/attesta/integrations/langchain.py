"""Attesta integration for LangChain and LangGraph.

Provides two main entry points:

* :class:`AttestaToolWrapper` -- wraps a list of LangChain tools so that
  every invocation passes through Attesta approval before execution.
* :func:`attesta_node` -- returns a LangGraph node function that filters
  tool calls in the graph state, allowing only approved calls to proceed.

Both require ``langchain-core`` at runtime.  Install with::

    pip install attesta[langchain]
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import functools
import logging
import threading
from typing import TYPE_CHECKING, Any

from attesta.core.gate import TRUSTED_RISK_OVERRIDE_METADATA_KEY
from attesta.core.types import ActionContext, Verdict

if TYPE_CHECKING:
    from attesta import Attesta

__all__ = ["AttestaToolWrapper", "attesta_node"]

logger = logging.getLogger("attesta.integrations.langchain")


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
        name="attesta-langchain-sync-bridge",
        daemon=True,
    )
    thread.start()
    return result_future.result(timeout=timeout)


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------

class AttestaToolWrapper:
    """Wraps LangChain tools with Attesta approval.

    Usage::

        from attesta import Attesta
        from attesta.integrations.langchain import AttestaToolWrapper

        gk = Attesta()
        wrapper = AttestaToolWrapper(gk)
        protected_tools = wrapper.wrap_tools(tools)

    Parameters
    ----------
    attesta:
        A configured :class:`~attesta.Attesta` instance.
    risk_overrides:
        Optional mapping of ``{tool_name: risk_level_str}`` that forces a
        specific risk level for named tools (e.g. ``{"delete_db": "critical"}``).
    """

    def __init__(
        self,
        attesta: Attesta,
        risk_overrides: dict[str, str] | None = None,
    ) -> None:
        self.gk = attesta
        self.risk_overrides: dict[str, str] = risk_overrides or {}

    def wrap_tools(self, tools: list[Any]) -> list[Any]:
        """Wrap a list of LangChain tools with attesta approval.

        Returns a **new** list of copied tools.  The original tool objects
        are **not** mutated.
        """
        return [self._wrap_tool(tool) for tool in tools]

    # -- internal ----------------------------------------------------------

    def _wrap_tool(self, tool: Any) -> Any:
        """Wrap a single LangChain tool, returning a new copy."""
        try:
            from langchain_core.tools import BaseTool  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "langchain-core is required for the LangChain integration. "
                "Install with: pip install attesta[langchain]"
            ) from exc

        wrapped = copy.copy(tool)

        original_func = tool.func if hasattr(tool, "func") else tool._run
        original_afunc: Any | None = (
            tool.coroutine if hasattr(tool, "coroutine") else None
        )
        gk = self.gk
        risk_override = self.risk_overrides.get(tool.name)

        @functools.wraps(original_func)
        def gated_func(*args: Any, **kwargs: Any) -> Any:
            ctx = _build_tool_context(tool, args, kwargs, risk_override)

            # Execute the async evaluate from a sync context.
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                # Already inside an event loop thread; avoid create_task()+result()
                # deadlock by running on a dedicated worker thread.
                result = _run_coroutine_in_worker_thread(
                    lambda: gk.evaluate(ctx),
                    timeout=300,
                )
            else:
                result = asyncio.run(gk.evaluate(ctx))

            return _handle_result(result, original_func, tool.name, args, kwargs)

        async def gated_afunc(*args: Any, **kwargs: Any) -> Any:
            ctx = _build_tool_context(tool, args, kwargs, risk_override)
            result = await gk.evaluate(ctx)

            if result.verdict in (Verdict.APPROVED, Verdict.MODIFIED):
                if original_afunc is not None:
                    return await original_afunc(*args, **kwargs)
                return original_func(*args, **kwargs)

            risk_label = result.risk_assessment.level.value
            logger.info(
                "Attesta denied tool %r (risk=%s)", tool.name, risk_label,
            )
            return (
                f"Action denied by Attesta: {tool.name} "
                f"(risk: {risk_label})"
            )

        wrapped.func = gated_func
        if original_afunc is not None:
            wrapped.coroutine = gated_afunc

        return wrapped


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------

def attesta_node(attesta: Attesta):
    """Create a LangGraph node that gates tool calls.

    Insert this node between the agent node and the tool-execution node so
    that only approved tool calls are forwarded.

    Usage with LangGraph::

        from langgraph.graph import StateGraph
        from attesta.integrations.langchain import attesta_node

        builder = StateGraph(State)
        builder.add_node("agent", agent_node)
        builder.add_node("gate", attesta_node(gk))
        builder.add_node("tools", tool_node)
        builder.add_edge("agent", "gate")
        builder.add_edge("gate", "tools")

    Returns
    -------
    Callable
        An async function suitable for use as a LangGraph node.
    """

    async def node_fn(state: dict[str, Any]) -> dict[str, Any]:
        messages = state.get("messages", [])
        if not messages:
            return state

        last_msg = messages[-1]

        # LangChain AI messages expose tool calls via a ``tool_calls`` attr.
        tool_calls: list[dict[str, Any]] | None = getattr(
            last_msg, "tool_calls", None,
        )
        if not tool_calls:
            return state

        approved_calls: list[dict[str, Any]] = []
        for call in tool_calls:
            ctx = ActionContext(
                function_name=call.get("name", "unknown"),
                kwargs=call.get("args", {}),
            )
            result = await attesta.evaluate(ctx)
            if result.verdict in (Verdict.APPROVED, Verdict.MODIFIED):
                approved_calls.append(call)
            else:
                logger.info(
                    "Attesta denied tool call %r in LangGraph node "
                    "(risk=%s)",
                    call.get("name"),
                    result.risk_assessment.level.value,
                )

        # Replace tool calls on the message with only the approved subset.
        if hasattr(last_msg, "tool_calls"):
            last_msg.tool_calls = approved_calls

        return state

    return node_fn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_tool_context(
    tool: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    risk_override: str | None,
) -> ActionContext:
    """Build an :class:`ActionContext` from a LangChain tool invocation."""
    hints: dict[str, Any] = {}
    metadata: dict[str, Any] = {"source": "langchain"}
    if risk_override is not None:
        hints["risk_override"] = risk_override
        metadata[TRUSTED_RISK_OVERRIDE_METADATA_KEY] = risk_override
    return ActionContext(
        function_name=tool.name,
        args=args,
        kwargs=kwargs,
        function_doc=getattr(tool, "description", None),
        hints=hints,
        metadata=metadata,
    )


def _handle_result(
    result: Any,
    original_func: Any,
    tool_name: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> Any:
    """Dispatch based on the approval verdict."""
    if result.verdict in (Verdict.APPROVED, Verdict.MODIFIED):
        return original_func(*args, **kwargs)

    risk_label = result.risk_assessment.level.value
    logger.info("Attesta denied tool %r (risk=%s)", tool_name, risk_label)
    return f"Action denied by Attesta: {tool_name} (risk: {risk_label})"
