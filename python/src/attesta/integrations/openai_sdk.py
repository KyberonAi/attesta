"""Attesta integration for the OpenAI Agents SDK.

Provides two integration points:

* :func:`attesta_approval_handler` -- a factory that returns an async
  approval handler compatible with the ``Runner.run(approval_handler=...)``
  parameter of the OpenAI Agents SDK.
* :class:`AttestaGuardrail` -- a callable class suitable for use as an
  element in an ``Agent``'s ``tool_guardrails`` list.

Install the optional dependency with::

    pip install attesta[openai]
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from attesta.core.types import ActionContext, Verdict

if TYPE_CHECKING:
    from attesta import Attesta

__all__ = ["attesta_approval_handler", "AttestaGuardrail"]

logger = logging.getLogger("attesta.integrations.openai_sdk")


# ---------------------------------------------------------------------------
# Approval handler (Runner-level)
# ---------------------------------------------------------------------------


def attesta_approval_handler(attesta: Attesta) -> Callable[..., Any]:
    """Create an approval handler for the OpenAI Agents SDK.

    The returned coroutine matches the ``approval_handler`` signature
    expected by ``Runner.run``::

        async def handler(tool_name: str, tool_args: dict, **kwargs) -> bool

    Usage::

        from openai.agents import Agent, Runner
        from attesta.integrations.openai_sdk import attesta_approval_handler

        gk = Attesta()
        result = await Runner.run(
            agent,
            input="Deploy to production",
            approval_handler=attesta_approval_handler(gk),
        )

    Parameters
    ----------
    attesta:
        A configured :class:`~attesta.Attesta` instance.

    Returns
    -------
    Callable
        An async function usable as an ``approval_handler``.
    """

    async def handler(tool_name: str, tool_args: dict[str, Any], **kwargs: Any) -> bool:
        ctx = ActionContext(
            function_name=tool_name,
            kwargs=tool_args,
            hints=kwargs,
        )
        result = await attesta.evaluate(ctx)
        approved = result.verdict in (Verdict.APPROVED, Verdict.MODIFIED)
        if not approved:
            logger.info(
                "Attesta denied tool %r via approval handler (risk=%s)",
                tool_name,
                result.risk_assessment.level.value,
            )
        return approved

    return handler


# ---------------------------------------------------------------------------
# Tool guardrail (Agent-level)
# ---------------------------------------------------------------------------


class AttestaGuardrail:
    """Use as a tool guardrail in the OpenAI Agents SDK.

    Instances are callable and match the ``tool_guardrails`` interface:
    they receive a tool name and input dict and return ``None`` to allow,
    or a ``dict`` with an ``"error"`` key to deny.

    Usage::

        from openai.agents import Agent
        from attesta.integrations.openai_sdk import AttestaGuardrail

        agent = Agent(
            tools=[my_tool],
            tool_guardrails=[AttestaGuardrail(gk)],
        )

    Parameters
    ----------
    attesta:
        A configured :class:`~attesta.Attesta` instance.
    """

    def __init__(self, attesta: Attesta) -> None:
        self.gk = attesta

    async def __call__(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> dict[str, str] | None:
        """Evaluate a tool invocation.

        Returns
        -------
        None
            If the action is approved (``None`` signals "allow").
        dict
            A dict with an ``"error"`` key if the action is denied.
        """
        ctx = ActionContext(
            function_name=tool_name,
            kwargs=tool_input,
        )
        result = await self.gk.evaluate(ctx)

        if result.verdict in (Verdict.APPROVED, Verdict.MODIFIED):
            return None

        risk_label = result.risk_assessment.level.value
        logger.info(
            "Attesta denied tool %r via guardrail (risk=%s)",
            tool_name,
            risk_label,
        )
        return {"error": f"Denied by Attesta (risk: {risk_label})"}
