"""Simple confirmation challenge for MEDIUM-risk actions.

Presents a human-readable summary of the pending action and waits for
explicit Y/N approval.  A configurable minimum review time prevents
reflexive "yes" responses by forcing the operator to wait before the
prompt becomes active.
"""

from __future__ import annotations

import asyncio
import time

from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
)


class ConfirmChallenge:
    """Simple Y/N confirmation with action summary.

    Parameters
    ----------
    min_review_seconds:
        Minimum wall-clock seconds the summary must be visible before the
        operator is allowed to approve.  Defaults to ``3.0``.
    """

    def __init__(self, min_review_seconds: float = 3.0) -> None:
        self.min_review_seconds = min_review_seconds

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.CONFIRM

    async def present(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> ChallengeResult:
        """Present a simple confirmation prompt.

        Enforces minimum review time before accepting input.
        Returns :class:`ChallengeResult` with ``passed=True`` if the operator
        confirms with ``y`` or ``yes``.
        """
        start = time.monotonic()

        # -- render action summary ----------------------------------------
        separator = "=" * 60
        print(f"\n{separator}")
        print(f"  Action: {ctx.function_name}")
        print(f"  Risk: {risk.level.value.upper()} ({risk.score:.2f})")
        if ctx.function_doc:
            print(f"  Description: {ctx.function_doc}")
        print(f"  Call: {ctx.description}")
        print(f"{separator}")

        # -- enforce minimum review time ----------------------------------
        elapsed = time.monotonic() - start
        if elapsed < self.min_review_seconds:
            remaining = self.min_review_seconds - elapsed
            print(f"  [Review for {remaining:.0f}s before approving...]")
            await asyncio.sleep(remaining)

        # -- collect response (blocking I/O delegated to executor) --------
        loop = asyncio.get_running_loop()

        def _read_input() -> str:
            try:
                return input("  Approve? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return ""

        response: str = await loop.run_in_executor(None, _read_input)
        elapsed = time.monotonic() - start

        approved = response in ("y", "yes")
        return ChallengeResult(
            passed=approved,
            challenge_type=self.challenge_type,
            response_time_seconds=elapsed,
            questions_asked=1,
            questions_correct=1 if approved else 0,
        )
