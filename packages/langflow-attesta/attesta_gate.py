"""Attesta Approval component for Langflow.

A human-in-the-loop approval component that evaluates AI agent actions for risk
before execution. This component integrates the Attesta framework into
Langflow workflows.

Contribution target: src/lfx/src/lfx/components/tools/attesta_gate.py
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

try:
    from lfx.custom.custom_component.component import Component
    from lfx.io import DropdownInput, MessageTextInput, Output
    from lfx.schema import Data
except ImportError:
    # Lightweight local stubs so this module remains importable in OSS CI
    # without the full Langflow runtime installed.
    class Component:  # type: ignore[no-redef]
        def log(self, _message: str) -> None:
            return None

    class _InputBase:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs

    class DropdownInput(_InputBase):  # type: ignore[no-redef]
        pass

    class MessageTextInput(_InputBase):  # type: ignore[no-redef]
        pass

    class Output(_InputBase):  # type: ignore[no-redef]
        pass

    class Data:  # type: ignore[no-redef]
        def __init__(self, data: dict[str, Any] | None = None) -> None:
            self.data = data or {}

from attesta.core.gate import Attesta
from attesta.core.types import ActionContext, RiskLevel, Verdict


class AttestaGate(Component):
    """Evaluates AI agent actions for risk and enforces approval policies."""

    display_name = "Attesta Approval"
    description = "Human-in-the-loop approval that evaluates AI agent actions for risk before execution"
    documentation = "https://attesta.dev"
    icon = "shield-check"
    name = "attesta_gate"

    inputs = [
        MessageTextInput(
            name="function_name",
            display_name="Function Name",
            info="Name of the action being gated (e.g. send_email, delete_record)",
            required=True,
        ),
        DropdownInput(
            name="risk_level",
            display_name="Risk Level",
            options=["auto", "low", "medium", "high", "critical"],
            value="auto",
            info="Risk level override. 'auto' uses the built-in risk scorer.",
        ),
        MessageTextInput(
            name="action_args",
            display_name="Action Arguments",
            info="JSON string of arguments to evaluate (e.g. {\"to\": \"user@example.com\"})",
            value="{}",
        ),
        MessageTextInput(
            name="risk_hints",
            display_name="Risk Hints",
            info="JSON string of risk hints (e.g. {\"destructive\": true, \"pii\": true})",
            value="{}",
            advanced=True,
        ),
    ]

    outputs = [
        Output(
            display_name="Approval Result",
            name="result",
            method="evaluate_gate",
        ),
    ]

    async def evaluate_gate(self) -> Data:
        """Evaluate the action through Attesta."""
        function_name: str = self.function_name
        risk_level_str: str = self.risk_level or "auto"

        # Parse JSON inputs
        action_args = self._parse_json(self.action_args, "action_args")
        risk_hints = self._parse_json(self.risk_hints, "risk_hints")

        # Determine risk override
        risk_override: RiskLevel | None = None
        if risk_level_str != "auto":
            risk_override = RiskLevel(risk_level_str)

        attesta = Attesta(
            risk_override=risk_override,
            risk_hints=risk_hints,
        )

        ctx = ActionContext(
            function_name=function_name,
            kwargs=action_args,
            hints=risk_hints,
            environment="production",
            metadata={"source": "langflow"},
        )

        result = await attesta.evaluate(ctx)

        denied = result.verdict in (
            Verdict.DENIED,
            Verdict.TIMED_OUT,
            Verdict.ESCALATED,
        )

        return Data(
            data={
                "verdict": result.verdict.value,
                "risk_score": result.risk_assessment.score,
                "risk_level": result.risk_assessment.level.value,
                "denied": denied,
                "audit_entry_id": result.audit_entry_id,
                "review_time_seconds": result.review_time_seconds,
                "function_name": function_name,
            }
        )

    def _parse_json(self, raw: str, field_name: str) -> dict[str, Any]:
        """Parse a JSON string input, returning {} on failure."""
        if not raw or raw.strip() == "":
            return {}
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return {}
        except (json.JSONDecodeError, TypeError):
            self.log(f"Warning: invalid JSON in {field_name}, using empty dict")
            return {}
