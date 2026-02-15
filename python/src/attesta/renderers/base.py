"""Abstract base class for attesta renderers.

A renderer is responsible for presenting approval prompts, challenges, and
informational messages to the operator.  Concrete implementations decide
*how* the UI is shown -- terminal, web, Slack, etc.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
    RiskLevel,
    Verdict,
)


class BaseRenderer(ABC):
    """Interface that every renderer must implement.

    The four methods map to the four user-facing moments in the approval
    pipeline:

    * **render_auto_approved** -- LOW-risk action, no human input needed.
    * **render_approval** -- MEDIUM-risk action, simple approve / deny.
    * **render_challenge** -- HIGH / CRITICAL risk, comprehension challenge.
    * **render_info** -- Informational message (no decision required).
    """

    @abstractmethod
    async def render_approval(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> Verdict:
        """Present an approval prompt and return the operator's verdict."""
        ...

    @abstractmethod
    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        """Present a verification challenge and return the result."""
        ...

    @abstractmethod
    async def render_auto_approved(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> None:
        """Notify the operator that a low-risk action was auto-approved."""
        ...

    @abstractmethod
    async def render_info(self, message: str) -> None:
        """Display a non-interactive informational message."""
        ...
