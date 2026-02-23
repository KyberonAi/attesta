"""Pluggable validators for teach-back challenge responses.

This module provides the ``TeachBackValidator`` protocol and the built-in
:class:`KeywordValidator` (word-count + key-term overlap).

Custom validators need only implement the two-method
:class:`TeachBackValidator` protocol.
"""

from __future__ import annotations

import re
from typing import Any, Protocol, runtime_checkable

from attesta.core.types import ActionContext


@runtime_checkable
class TeachBackValidator(Protocol):
    """Protocol for validating teach-back explanations.

    Implementations receive the operator's free-text explanation and the
    :class:`ActionContext` and return ``(passed, notes)`` where *notes*
    is a human-readable string explaining the verdict.
    """

    async def validate(self, explanation: str, context: ActionContext) -> tuple[bool, str]:
        """Validate *explanation* against *context*.

        Returns
        -------
        tuple[bool, str]
            ``(passed, notes)``
        """
        ...


def _extract_key_terms(ctx: ActionContext) -> list[str]:
    """Derive key terms from the action context.

    This is the canonical implementation, imported by the teach_back module.
    """
    terms: list[str] = []

    # Function name parts
    name_parts = re.sub(r"([a-z])([A-Z])", r"\1 \2", ctx.function_name)
    name_parts = name_parts.replace("-", " ").replace("_", " ")
    for word in name_parts.split():
        cleaned = word.strip().lower()
        if len(cleaned) > 2:
            terms.append(cleaned)

    # Significant argument values
    all_values: list[Any] = list(ctx.args) + list(ctx.kwargs.values())
    for val in all_values:
        if isinstance(val, str) and len(val) > 2:
            if "/" in val or "\\" in val:
                import os

                terms.append(os.path.basename(val).lower())
            if len(val) <= 80:
                terms.append(val.strip().lower())
        elif isinstance(val, (int, float)) and not isinstance(val, bool):
            terms.append(str(val))

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in terms:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


class KeywordValidator:
    """Default validator using word count and key-term overlap.

    This extracts the same inline validation logic that was previously
    embedded in ``TeachBackChallenge.present()``.

    Parameters
    ----------
    min_words:
        Minimum word count for the explanation.
    """

    def __init__(self, min_words: int = 15) -> None:
        self.min_words = min_words

    async def validate(self, explanation: str, context: ActionContext) -> tuple[bool, str]:
        notes: list[str] = []

        # Word count check
        word_count = len(explanation.split())
        length_ok = word_count >= self.min_words
        if not length_ok:
            notes.append(f"Too short: {word_count} words (minimum {self.min_words}).")

        # Key-term overlap check
        key_terms = _extract_key_terms(context)
        explanation_lower = explanation.lower()
        matched_terms = [t for t in key_terms if t in explanation_lower]
        terms_ok = len(matched_terms) >= 1
        if not terms_ok:
            notes.append(
                f"No key terms from the action context found in explanation. Expected at least one of: {key_terms[:6]}"
            )
        else:
            notes.append(f"Matched key terms: {matched_terms}")

        passed = length_ok and terms_ok
        return passed, "; ".join(notes) if notes else "Keyword validation passed."
