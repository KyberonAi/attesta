"""Multi-party approval challenge for CRITICAL+ risk actions.

Requires two or more independent human approvers, each of whom must pass
their own sub-challenge (confirm, quiz, or teach-back) before the action
is allowed to proceed.  This is the highest-assurance challenge level
offered by attesta.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
)

from attesta.challenges.confirm import ConfirmChallenge
from attesta.challenges.quiz import QuizChallenge
from attesta.challenges.teach_back import TeachBackChallenge


# ---------------------------------------------------------------------------
# Per-approver record
# ---------------------------------------------------------------------------

@dataclass
class ApproverRecord:
    """Audit record for a single approver within a multi-party challenge."""

    approver_id: str
    challenge_type: ChallengeType
    passed: bool
    response_time_seconds: float
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Default sub-challenge rotation
# ---------------------------------------------------------------------------

_DEFAULT_SUB_CHALLENGES: list[ConfirmChallenge | QuizChallenge | TeachBackChallenge] = [
    TeachBackChallenge(min_review_seconds=15.0),
    QuizChallenge(min_review_seconds=5.0),
    ConfirmChallenge(min_review_seconds=3.0),
]


# ---------------------------------------------------------------------------
# MultiPartyChallenge
# ---------------------------------------------------------------------------

class MultiPartyChallenge:
    """Multi-party approval requiring 2+ independent human approvers.

    Each approver is assigned a **different** sub-challenge drawn from a
    rotating pool (teach-back, quiz, confirm).  The first approver always
    receives the hardest challenge; subsequent approvers rotate through
    progressively lighter challenges.

    In terminal mode approvals are collected **sequentially** -- each
    approver takes their turn at the same terminal.  The class is designed
    so that async / parallel collection (e.g. via Slack, web UI) can be
    added by subclassing and overriding :meth:`_collect_approval`.

    **All** approvers must pass for the overall challenge to succeed.

    Parameters
    ----------
    required_approvers:
        Number of independent approvals required (minimum 2).
    sub_challenges:
        Ordered sequence of sub-challenge instances to rotate through.
        Defaults to ``[TeachBackChallenge, QuizChallenge, ConfirmChallenge]``.
    min_review_seconds:
        Additional per-approver minimum review time layered on top of
        each sub-challenge's own minimum.  Defaults to ``0.0`` (rely on
        sub-challenge timings).
    """

    def __init__(
        self,
        required_approvers: int = 2,
        sub_challenges: Sequence[ConfirmChallenge | QuizChallenge | TeachBackChallenge] | None = None,
        min_review_seconds: float = 0.0,
    ) -> None:
        if required_approvers < 2:
            raise ValueError(
                f"Multi-party approval requires at least 2 approvers, "
                f"got {required_approvers}."
            )
        self.required_approvers = required_approvers
        self.sub_challenges = list(sub_challenges or _DEFAULT_SUB_CHALLENGES)
        self.min_review_seconds = min_review_seconds

        if not self.sub_challenges:
            raise ValueError("At least one sub-challenge must be provided.")

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.MULTI_PARTY

    # -- per-approver collection ------------------------------------------

    async def _collect_approval(
        self,
        approver_index: int,
        ctx: ActionContext,
        risk: RiskAssessment,
    ) -> ApproverRecord:
        """Collect a single approval in terminal (sequential) mode.

        Subclass and override this method to support parallel / remote
        collection (e.g. Slack, web hooks).
        """
        loop = asyncio.get_running_loop()
        sub = self.sub_challenges[approver_index % len(self.sub_challenges)]

        separator = "-" * 60
        print(f"\n{separator}")
        print(
            f"  Approver {approver_index + 1} / {self.required_approvers}  "
            f"({sub.challenge_type.value.upper()} challenge)"
        )
        print(f"{separator}")

        # Ask for approver identity
        approver_id: str = await loop.run_in_executor(
            None,
            lambda: input("  Enter your name or ID: ").strip(),
        )
        if not approver_id:
            approver_id = f"approver_{approver_index + 1}"

        # Enforce optional extra review time
        if self.min_review_seconds > 0:
            print(
                f"  [Mandatory review period: {self.min_review_seconds:.0f}s...]"
            )
            await asyncio.sleep(self.min_review_seconds)

        start = time.monotonic()
        result: ChallengeResult = await sub.present(ctx, risk)
        elapsed = time.monotonic() - start

        return ApproverRecord(
            approver_id=approver_id,
            challenge_type=sub.challenge_type,
            passed=result.passed,
            response_time_seconds=elapsed,
            details={
                "sub_challenge_result": {
                    "passed": result.passed,
                    "challenge_type": result.challenge_type.value,
                    "response_time_seconds": result.response_time_seconds,
                    "questions_asked": result.questions_asked,
                    "questions_correct": result.questions_correct,
                    "details": result.details,
                },
            },
        )

    # -- public interface -------------------------------------------------

    async def present(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> ChallengeResult:
        """Run the full multi-party approval flow.

        Returns a :class:`ChallengeResult` where ``passed`` is ``True``
        only if **every** required approver passed their sub-challenge.
        """
        overall_start = time.monotonic()

        separator = "=" * 60
        print(f"\n{separator}")
        print(f"  MULTI-PARTY APPROVAL  --  CRITICAL+ RISK ACTION")
        print(f"  Requires {self.required_approvers} independent approvals")
        print(f"{separator}")
        print(f"  Action: {ctx.function_name}")
        print(f"  Risk:   {risk.level.value.upper()} ({risk.score:.2f})")
        print(f"  Call:   {ctx.description}")
        print(f"{separator}")

        records: list[ApproverRecord] = []
        all_passed = True

        for i in range(self.required_approvers):
            record = await self._collect_approval(i, ctx, risk)
            records.append(record)

            if record.passed:
                print(f"\n  Approver '{record.approver_id}': APPROVED")
            else:
                print(f"\n  Approver '{record.approver_id}': DENIED")
                all_passed = False
                # Early termination: no point continuing once one fails
                print("  Multi-party approval FAILED (all approvers must pass).")
                break

        elapsed = time.monotonic() - overall_start

        passed_count = sum(1 for r in records if r.passed)
        status = "PASSED" if all_passed else "FAILED"
        print(f"\n{separator}")
        print(
            f"  Multi-party result: {status} "
            f"({passed_count}/{self.required_approvers} approved)"
        )
        print(f"{separator}")

        return ChallengeResult(
            passed=all_passed,
            challenge_type=self.challenge_type,
            response_time_seconds=elapsed,
            questions_asked=self.required_approvers,
            questions_correct=passed_count,
            details={
                "required_approvers": self.required_approvers,
                "approver_records": [
                    {
                        "approver_id": r.approver_id,
                        "challenge_type": r.challenge_type.value,
                        "passed": r.passed,
                        "response_time_seconds": r.response_time_seconds,
                        "details": r.details,
                    }
                    for r in records
                ],
            },
        )
