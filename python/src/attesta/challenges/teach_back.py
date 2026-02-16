"""Teach-back challenge for CRITICAL-risk actions.

The operator must explain, in their own words, what the action will do
and what its effects are.  This is the strongest single-person challenge
because it requires *active* comprehension rather than passive recognition.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from attesta.core.types import (
    ActionContext,
    ChallengeResult,
    ChallengeType,
    RiskAssessment,
)
from attesta.challenges.validators import _extract_key_terms


class TeachBackChallenge:
    """Teach-back verification for CRITICAL-risk actions.

    The operator is shown the full action details and asked to explain, in
    their own words, what the action will do and what its effects are.

    Validation rules:

    1. The response must be at least *min_words* words long.
    2. The response must contain at least one **key term** extracted from
       the action context (function name parts, significant arg values).
    3. *(Optional)* If a custom ``validator`` is provided, it can apply
       additional comprehension checks.

    Parameters
    ----------
    min_words:
        Minimum word count for the operator's explanation.
    min_review_seconds:
        Wall-clock seconds the action summary must be visible before the
        prompt becomes active.
    validator:
        Pluggable validator implementing ``TeachBackValidator`` protocol.
        Defaults to ``KeywordValidator(min_words=min_words)``.
    """

    def __init__(
        self,
        min_words: int = 15,
        min_review_seconds: float = 30.0,
        validator: Any = None,
    ) -> None:
        self.min_words = min_words
        self.min_review_seconds = min_review_seconds

        if validator is not None:
            self._validator = validator
        else:
            from attesta.challenges.validators import KeywordValidator
            self._validator = KeywordValidator(min_words=min_words)

    @property
    def challenge_type(self) -> ChallengeType:
        return ChallengeType.TEACH_BACK

    # -- presentation -----------------------------------------------------

    async def present(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> ChallengeResult:
        """Present the teach-back challenge to the operator."""
        start = time.monotonic()
        loop = asyncio.get_running_loop()

        # -- render full action details -----------------------------------
        separator = "=" * 60
        print(f"\n{separator}")
        print(f"  TEACH-BACK CHALLENGE  --  CRITICAL RISK ACTION")
        print(f"{separator}")
        print(f"  Action:      {ctx.function_name}")
        print(f"  Risk:        {risk.level.value.upper()} ({risk.score:.2f})")
        if ctx.function_doc:
            print(f"  Description: {ctx.function_doc}")
        print(f"  Call:        {ctx.description}")
        if ctx.args:
            print(f"  Positional:  {ctx.args!r}")
        if ctx.kwargs:
            print(f"  Keyword:     {ctx.kwargs!r}")
        if risk.factors:
            print(f"  Risk factors:")
            for factor in risk.factors:
                print(f"    - {factor.name}: {factor.description}")
        print(f"{separator}")

        # -- enforce minimum review time ----------------------------------
        elapsed = time.monotonic() - start
        if elapsed < self.min_review_seconds:
            remaining = self.min_review_seconds - elapsed
            print(f"  [Read carefully. Prompt activates in {remaining:.0f}s...]")
            await asyncio.sleep(remaining)

        # -- collect free-text explanation --------------------------------
        print(
            "\n  In your own words, explain what this action will do and "
            "what its effects are:"
        )

        def _read_input() -> str:
            try:
                return input("  > ").strip()
            except (EOFError, KeyboardInterrupt):
                return ""

        explanation: str = await loop.run_in_executor(None, _read_input)

        # -- validate via pluggable validator -----------------------------
        passed, validation_note = await self._validator.validate(explanation, ctx)
        validation_notes: list[str] = [validation_note]

        # Extract details for backward-compatible result structure
        key_terms = _extract_key_terms(ctx)
        explanation_lower = explanation.lower()
        matched_terms = [t for t in key_terms if t in explanation_lower]
        word_count = len(explanation.split())
        elapsed = time.monotonic() - start

        status = "PASSED" if passed else "FAILED"
        print(f"\n  Teach-back result: {status}")
        for note in validation_notes:
            print(f"    - {note}")

        return ChallengeResult(
            passed=passed,
            challenge_type=self.challenge_type,
            response_time_seconds=elapsed,
            questions_asked=1,
            questions_correct=1 if passed else 0,
            details={
                "explanation": explanation,
                "word_count": word_count,
                "key_terms": key_terms,
                "matched_terms": matched_terms,
                "passed": passed,
                "validation_notes": validation_notes,
            },
        )
