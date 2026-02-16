"""Attesta integration for CrewAI.

Provides :class:`AttestaHumanInput`, a callable that can be used as a
CrewAI task callback in place of (or alongside) the built-in ``human_input``
flag.  When a task completes, Attesta evaluates the output before the
workflow continues.

Install the optional dependency with::

    pip install attesta[crewai]
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from attesta.core.gate import TRUSTED_RISK_OVERRIDE_METADATA_KEY
from attesta.core.types import ActionContext, Verdict

if TYPE_CHECKING:
    from attesta import Attesta

__all__ = ["AttestaHumanInput"]

logger = logging.getLogger("attesta.integrations.crewai")

# Maximum length of the task description sent as ``function_doc``.
_MAX_DOC_LENGTH = 200


class AttestaHumanInput:
    """Drop-in replacement for CrewAI's human_input that uses Attesta.

    Attach an instance as a task ``callback`` so that every task output is
    gated through the configured approval pipeline::

        from crewai import Task
        from attesta.integrations.crewai import AttestaHumanInput

        gk_input = AttestaHumanInput(gk)
        task = Task(
            description="Deploy service",
            human_input=True,
            callback=gk_input,
        )

    Parameters
    ----------
    attesta:
        A configured :class:`~attesta.Attesta` instance.
    default_risk:
        Optional risk level string (e.g. ``"high"``) applied when no other
        risk information is available.  Passed to the scorer via
        ``ActionContext.hints["risk_override"]``.
    """

    def __init__(
        self,
        attesta: Attesta,
        default_risk: str | None = None,
    ) -> None:
        self.gk = attesta
        self.default_risk = default_risk

    async def __call__(self, task_output: Any) -> str:
        """Evaluate *task_output* through Attesta.

        Parameters
        ----------
        task_output:
            The CrewAI task output object (stringified for context).

        Returns
        -------
        str
            ``"approved"`` if the gate passes, otherwise ``"denied"``.
        """
        description = str(task_output) if task_output else "CrewAI task output"
        hints: dict[str, Any] = {}
        metadata: dict[str, Any] = {"source": "crewai"}
        if self.default_risk is not None:
            hints["risk_override"] = self.default_risk
            metadata[TRUSTED_RISK_OVERRIDE_METADATA_KEY] = self.default_risk

        ctx = ActionContext(
            function_name="crewai_task",
            kwargs={"output": description},
            function_doc=description[:_MAX_DOC_LENGTH],
            hints=hints,
            metadata=metadata,
        )

        result = await self.gk.evaluate(ctx)

        if result.verdict in (Verdict.APPROVED, Verdict.MODIFIED):
            logger.debug("CrewAI task output approved (risk=%s)", result.risk_assessment.level.value)
            return "approved"

        logger.info(
            "CrewAI task output denied (risk=%s)", result.risk_assessment.level.value,
        )
        return "denied"
