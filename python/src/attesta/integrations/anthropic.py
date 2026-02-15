"""Attesta integration for the Anthropic Claude API.

Provides :class:`AttestaToolGate`, which evaluates ``tool_use`` content
blocks from Claude's response through the Attesta approval pipeline
before the host application executes the requested tool.

Install the optional dependency with::

    pip install attesta[anthropic]
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from attesta.core.types import ActionContext, ApprovalResult

if TYPE_CHECKING:
    from attesta import Attesta

__all__ = ["AttestaToolGate"]

logger = logging.getLogger("attesta.integrations.anthropic")


class AttestaToolGate:
    """Gates Anthropic Claude ``tool_use`` blocks through Attesta.

    Typical usage::

        from anthropic import Anthropic
        from attesta.integrations.anthropic import AttestaToolGate

        client = Anthropic()
        gate = AttestaToolGate(gk)

        response = client.messages.create(...)

        for block in response.content:
            if block.type == "tool_use":
                approved, result = await gate.evaluate_tool_use(block)
                if approved:
                    # execute the tool
                    ...
                else:
                    # send a denial back to Claude
                    denial = gate.make_denial_result(
                        block.id, reason=f"risk: {result.risk_assessment.level.value}"
                    )

    Parameters
    ----------
    attesta:
        A configured :class:`~attesta.Attesta` instance.
    risk_overrides:
        Optional mapping of ``{tool_name: risk_level_str}`` that forces a
        specific risk level for named tools (e.g. ``{"run_bash": "critical"}``).
    """

    def __init__(
        self,
        attesta: Attesta,
        risk_overrides: dict[str, str] | None = None,
    ) -> None:
        self.gk = attesta
        self.risk_overrides: dict[str, str] = risk_overrides or {}

    async def evaluate_tool_use(
        self,
        tool_use_block: Any,
    ) -> tuple[bool, ApprovalResult]:
        """Evaluate a ``tool_use`` block from Claude's response.

        Accepts both the Anthropic SDK's ``ToolUseBlock`` object (attribute
        access) and a plain ``dict`` representation (key access).

        Parameters
        ----------
        tool_use_block:
            A ``tool_use`` content block, either as an SDK object or dict.

        Returns
        -------
        tuple[bool, ApprovalResult]
            A two-tuple of ``(approved, approval_result)``.
        """
        tool_name = (
            tool_use_block.name
            if hasattr(tool_use_block, "name")
            else tool_use_block.get("name", "unknown")
        )
        tool_input = (
            tool_use_block.input
            if hasattr(tool_use_block, "input")
            else tool_use_block.get("input", {})
        )

        hints: dict[str, Any] = {}
        if tool_name in self.risk_overrides:
            hints["risk_override"] = self.risk_overrides[tool_name]

        ctx = ActionContext(
            function_name=tool_name,
            kwargs=tool_input if isinstance(tool_input, dict) else {"input": tool_input},
            hints=hints,
            agent_id="claude",
        )

        result = await self.gk.evaluate(ctx)
        approved = result.verdict.value in ("approved", "modified")

        if not approved:
            logger.info(
                "Attesta denied Claude tool_use %r (risk=%s)",
                tool_name,
                result.risk_assessment.level.value,
            )

        return approved, result

    @staticmethod
    def make_denial_result(
        tool_use_id: str,
        reason: str = "Denied by Attesta",
    ) -> dict[str, Any]:
        """Create a ``tool_result`` block indicating denial.

        The returned dict can be appended to the ``messages`` list sent back
        to Claude so it understands the tool call was rejected.

        Parameters
        ----------
        tool_use_id:
            The ``id`` from the original ``tool_use`` block.
        reason:
            A human-readable denial reason included in the error message.

        Returns
        -------
        dict
            A ``tool_result`` content block with ``is_error=True``.
        """
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": (
                f"[ATTESTA DENIED] {reason}. "
                "Please suggest an alternative approach or explain "
                "why this action is necessary."
            ),
            "is_error": True,
        }
