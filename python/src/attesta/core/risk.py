"""Risk scoring engine for attesta.

This module provides concrete :class:`RiskScorer` implementations that analyze
an :class:`ActionContext` and produce a continuous risk score in [0.0, 1.0].

Scorers can be used individually or composed together:

    >>> scorer = CompositeRiskScorer([
    ...     (DefaultRiskScorer(), 0.7),
    ...     (FixedRiskScorer(0.5), 0.3),
    ... ])
    >>> assessment = scorer.assess(ctx)

All public scorers expose:

* ``score(ctx) -> float`` -- satisfies the :class:`RiskScorer` protocol.
* ``assess(ctx) -> RiskAssessment`` -- convenience that wraps the raw score
  with :class:`RiskLevel`, contributing :class:`RiskFactor` details, and the
  scorer name.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Sequence

from attesta.core.types import (
    ActionContext,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
)

__all__ = [
    "DefaultRiskScorer",
    "CompositeRiskScorer",
    "MaxRiskScorer",
    "FixedRiskScorer",
]

# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

_DESTRUCTIVE_VERBS: frozenset[str] = frozenset(
    {"delete", "remove", "drop", "destroy", "purge", "truncate", "kill"}
)

_MUTATING_VERBS: frozenset[str] = frozenset(
    {
        "write", "update", "modify", "set", "create", "send",
        "deploy", "push", "execute", "run",
    }
)

_READ_VERBS: frozenset[str] = frozenset(
    {"read", "get", "list", "fetch", "search", "find", "check"}
)

_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"prod(uction)?", re.IGNORECASE),
    re.compile(r"\.env\b", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"\bkey\b", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
)

_SQL_DANGER: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bDROP\b", re.IGNORECASE),
    re.compile(r"\bDELETE\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
    re.compile(r"\bALTER\b", re.IGNORECASE),
)

_SHELL_DANGER: tuple[re.Pattern[str], ...] = (
    re.compile(r"rm\s+-rf\b"),
    re.compile(r"\bsudo\b"),
    re.compile(r"chmod\s+777\b"),
)

_NETWORK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
)

_DOCSTRING_HIGH: tuple[re.Pattern[str], ...] = (
    re.compile(r"irreversible", re.IGNORECASE),
    re.compile(r"permanent", re.IGNORECASE),
    re.compile(r"destructive", re.IGNORECASE),
    re.compile(r"dangerous", re.IGNORECASE),
    re.compile(r"production", re.IGNORECASE),
    re.compile(r"critical", re.IGNORECASE),
)

_DOCSTRING_MEDIUM: tuple[re.Pattern[str], ...] = (
    re.compile(r"careful", re.IGNORECASE),
    re.compile(r"warning", re.IGNORECASE),
    re.compile(r"caution", re.IGNORECASE),
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp *value* to the closed interval [lo, hi]."""
    return max(lo, min(hi, value))


def _flatten_args(args: tuple, kwargs: dict[str, Any]) -> list[str]:
    """Recursively stringify all positional and keyword arguments."""
    parts: list[str] = []
    for a in args:
        parts.append(str(a))
    for v in kwargs.values():
        parts.append(str(v))
    return parts


def _extract_verbs(function_name: str) -> list[str]:
    """Split a function name on underscores / camelCase and return lowercase tokens."""
    # Replace camelCase boundaries with underscores first, then split.
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", function_name)
    return [tok.lower() for tok in re.split(r"[_.\-/]+", snake) if tok]


# ---------------------------------------------------------------------------
# DefaultRiskScorer
# ---------------------------------------------------------------------------

@dataclass
class DefaultRiskScorer:
    """Built-in heuristic risk scorer.

    Analyzes five independent factors of an :class:`ActionContext` and produces
    a weighted composite score:

    +-------------------+--------+------------------------------------------+
    | Factor            | Weight | Signal                                   |
    +===================+========+==========================================+
    | function_name     | 0.30   | Destructive / mutating / read verbs      |
    | arguments         | 0.25   | Sensitive values, SQL, shell commands     |
    | docstring         | 0.20   | Danger / caution keywords                |
    | hints             | 0.15   | Caller-supplied risk metadata            |
    | novelty           | 0.10   | How often this function has been scored   |
    +-------------------+--------+------------------------------------------+

    The scorer is stateful: it maintains a call counter for the novelty
    factor.  Instances are **not** thread-safe -- use one per thread or
    protect with a lock.
    """

    # Weights for each factor (must sum to 1.0).
    weight_function: float = 0.30
    weight_args: float = 0.25
    weight_docstring: float = 0.20
    weight_hints: float = 0.15
    weight_novelty: float = 0.10

    # Internal state: call counter per function name for novelty tracking.
    _call_counts: Counter[str] = field(default_factory=Counter)

    # -- Protocol properties ---------------------------------------------------

    @property
    def name(self) -> str:
        """Scorer identifier used in :class:`RiskAssessment`."""
        return "default"

    # -- Public API ------------------------------------------------------------

    def score(self, ctx: ActionContext) -> float:
        """Return a risk score in [0.0, 1.0] for the given action context."""
        factors = self._compute_factors(ctx)
        total = sum(f.contribution for f in factors)
        return _clamp(total)

    def assess(self, ctx: ActionContext) -> RiskAssessment:
        """Produce a full :class:`RiskAssessment` with factor breakdown."""
        factors = self._compute_factors(ctx)
        raw = sum(f.contribution for f in factors)
        clamped = _clamp(raw)
        return RiskAssessment(
            score=clamped,
            level=RiskLevel.from_score(clamped),
            factors=factors,
            scorer_name=self.name,
        )

    # -- Factor computation ----------------------------------------------------

    def _compute_factors(self, ctx: ActionContext) -> list[RiskFactor]:
        """Evaluate all factors and return the list of weighted contributions."""
        factors: list[RiskFactor] = []

        fn_score, fn_evidence = self._score_function_name(ctx.function_name)
        factors.append(RiskFactor(
            name="function_name",
            contribution=fn_score * self.weight_function,
            description="Risk inferred from the function name verbs.",
            evidence=fn_evidence,
        ))

        arg_score, arg_evidence = self._score_arguments(ctx.args, ctx.kwargs)
        factors.append(RiskFactor(
            name="arguments",
            contribution=arg_score * self.weight_args,
            description="Risk inferred from argument values.",
            evidence=arg_evidence,
        ))

        doc_score, doc_evidence = self._score_docstring(ctx.function_doc)
        factors.append(RiskFactor(
            name="docstring",
            contribution=doc_score * self.weight_docstring,
            description="Risk inferred from the function docstring.",
            evidence=doc_evidence,
        ))

        hint_score, hint_evidence = self._score_hints(ctx.hints)
        factors.append(RiskFactor(
            name="hints",
            contribution=hint_score * self.weight_hints,
            description="Risk inferred from caller-supplied hints.",
            evidence=hint_evidence,
        ))

        nov_score, nov_evidence = self._score_novelty(ctx.function_name)
        factors.append(RiskFactor(
            name="novelty",
            contribution=nov_score * self.weight_novelty,
            description="Risk due to function call novelty.",
            evidence=nov_evidence,
        ))

        return factors

    # -- Individual factor scorers ---------------------------------------------

    @staticmethod
    def _score_function_name(function_name: str) -> tuple[float, str]:
        """Analyse the function name for destructive / mutating / read verbs.

        Returns:
            A ``(score, evidence)`` tuple where *score* is in [0, 1].
        """
        tokens = _extract_verbs(function_name)
        if not tokens:
            return 0.5, "no recognisable tokens"

        destructive = [t for t in tokens if t in _DESTRUCTIVE_VERBS]
        mutating = [t for t in tokens if t in _MUTATING_VERBS]
        reading = [t for t in tokens if t in _READ_VERBS]

        if destructive:
            return 0.95, f"destructive verbs: {', '.join(destructive)}"
        if mutating:
            return 0.55, f"mutating verbs: {', '.join(mutating)}"
        if reading:
            return 0.1, f"read verbs: {', '.join(reading)}"

        # Unknown verb -- treat as moderate uncertainty.
        return 0.4, "no known verb category matched"

    @staticmethod
    def _score_arguments(args: tuple, kwargs: dict[str, Any]) -> tuple[float, str]:
        """Scan stringified arguments for sensitive patterns.

        Returns:
            A ``(score, evidence)`` tuple where *score* is in [0, 1].
        """
        flat = _flatten_args(args, kwargs)
        if not flat:
            return 0.0, "no arguments"

        combined = " ".join(flat)
        evidence_parts: list[str] = []
        max_score = 0.0

        # High-risk: sensitive values.
        for pat in _SENSITIVE_PATTERNS:
            match = pat.search(combined)
            if match:
                evidence_parts.append(f"sensitive pattern '{match.group()}'")
                max_score = max(max_score, 0.9)

        # High-risk: dangerous SQL.
        for pat in _SQL_DANGER:
            match = pat.search(combined)
            if match:
                evidence_parts.append(f"SQL keyword '{match.group()}'")
                max_score = max(max_score, 0.9)

        # High-risk: dangerous shell commands.
        for pat in _SHELL_DANGER:
            match = pat.search(combined)
            if match:
                evidence_parts.append(f"shell command '{match.group()}'")
                max_score = max(max_score, 0.9)

        # Medium-risk: URLs, emails, IPs.
        for pat in _NETWORK_PATTERNS:
            match = pat.search(combined)
            if match:
                evidence_parts.append(f"network pattern '{match.group()}'")
                max_score = max(max_score, 0.5)

        if evidence_parts:
            return max_score, "; ".join(evidence_parts)
        return 0.05, "arguments appear benign"

    @staticmethod
    def _score_docstring(doc: str | None) -> tuple[float, str]:
        """Scan the docstring for danger / caution keywords.

        Returns:
            A ``(score, evidence)`` tuple where *score* is in [0, 1].
        """
        if not doc:
            return 0.1, "no docstring available"

        evidence_parts: list[str] = []
        max_score = 0.0

        for pat in _DOCSTRING_HIGH:
            match = pat.search(doc)
            if match:
                evidence_parts.append(f"high-risk keyword '{match.group()}'")
                max_score = max(max_score, 0.85)

        for pat in _DOCSTRING_MEDIUM:
            match = pat.search(doc)
            if match:
                evidence_parts.append(f"caution keyword '{match.group()}'")
                max_score = max(max_score, 0.5)

        if evidence_parts:
            return max_score, "; ".join(evidence_parts)
        return 0.05, "docstring contains no risk keywords"

    @staticmethod
    def _score_hints(hints: dict[str, Any]) -> tuple[float, str]:
        """Evaluate caller-provided risk hints.

        Hints are a flat ``dict[str, Any]`` where:

        * **Boolean** values add a flat 0.3 contribution when ``True``.
        * **Numeric** values are scaled: ``min(value / 10_000, 1.0) * 0.8``,
          capping at 0.8 contribution per hint.
        * Other types are ignored.

        The final score is the sum of all contributions, clamped to [0, 1].

        Returns:
            A ``(score, evidence)`` tuple where *score* is in [0, 1].
        """
        if not hints:
            return 0.0, "no hints provided"

        total = 0.0
        evidence_parts: list[str] = []

        for key, value in hints.items():
            if isinstance(value, bool):
                if value:
                    total += 0.3
                    evidence_parts.append(f"{key}=True (+0.30)")
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                contribution = min(value / 10_000, 1.0) * 0.8
                total += contribution
                evidence_parts.append(f"{key}={value} (+{contribution:.2f})")

        clamped = _clamp(total)
        if evidence_parts:
            return clamped, "; ".join(evidence_parts)
        return 0.0, "hints contained no scorable values"

    def _score_novelty(self, function_name: str) -> tuple[float, str]:
        """Assign a novelty score based on how often this function has been seen.

        First call:  score = 0.9  (highly novel)
        2nd-10th:    linearly decreases from 0.9 to 0.1
        10+:         score = 0.1  (well-known)

        The call counter is incremented **after** scoring so that the first
        invocation always receives the highest novelty score.

        Returns:
            A ``(score, evidence)`` tuple where *score* is in [0, 1].
        """
        count = self._call_counts[function_name]
        self._call_counts[function_name] += 1

        if count == 0:
            score = 0.9
        elif count >= 10:
            score = 0.1
        else:
            # Linear interpolation: count 1 -> 0.81, count 9 -> 0.18 ...
            score = 0.9 - (count / 10) * 0.8

        return score, f"seen {count} time(s) before"

    def reset_novelty(self) -> None:
        """Clear the internal call counter (useful in tests)."""
        self._call_counts.clear()


# ---------------------------------------------------------------------------
# CompositeRiskScorer
# ---------------------------------------------------------------------------

@dataclass
class CompositeRiskScorer:
    """Combines multiple scorers via a weighted average.

    Example::

        scorer = CompositeRiskScorer([
            (DefaultRiskScorer(), 0.7),
            (my_custom_scorer, 0.3),
        ])

    Weights do **not** need to sum to 1.0 -- they are normalised internally.
    A ``ValueError`` is raised if no scorers are provided.
    """

    scorers: Sequence[tuple[Any, float]]
    """Sequence of (scorer, weight) pairs.  Each scorer must satisfy the
    :class:`RiskScorer` protocol (i.e. expose ``score(ctx)`` and ``name``)."""

    def __post_init__(self) -> None:
        if not self.scorers:
            raise ValueError("CompositeRiskScorer requires at least one scorer")
        total_weight = sum(w for _, w in self.scorers)
        if total_weight <= 0:
            raise ValueError("Total weight must be positive")

    @property
    def name(self) -> str:
        """Scorer identifier."""
        names = "+".join(s.name for s, _ in self.scorers)
        return f"composite({names})"

    def score(self, ctx: ActionContext) -> float:
        """Return the weighted-average score across all child scorers."""
        total_weight = sum(w for _, w in self.scorers)
        weighted_sum = sum(s.score(ctx) * w for s, w in self.scorers)
        return _clamp(weighted_sum / total_weight)

    def assess(self, ctx: ActionContext) -> RiskAssessment:
        """Produce a :class:`RiskAssessment` with a factor for each child scorer."""
        total_weight = sum(w for _, w in self.scorers)
        factors: list[RiskFactor] = []
        weighted_sum = 0.0

        for scorer, weight in self.scorers:
            child_score = scorer.score(ctx)
            normalised_weight = weight / total_weight
            contribution = child_score * normalised_weight
            weighted_sum += contribution
            factors.append(RiskFactor(
                name=f"scorer:{scorer.name}",
                contribution=contribution,
                description=(
                    f"Score {child_score:.3f} from '{scorer.name}' "
                    f"(weight {normalised_weight:.2f})"
                ),
            ))

        clamped = _clamp(weighted_sum)
        return RiskAssessment(
            score=clamped,
            level=RiskLevel.from_score(clamped),
            factors=factors,
            scorer_name=self.name,
        )


# ---------------------------------------------------------------------------
# MaxRiskScorer
# ---------------------------------------------------------------------------

@dataclass
class MaxRiskScorer:
    """Takes the **maximum** score from multiple scorers (most conservative).

    Example::

        scorer = MaxRiskScorer([DefaultRiskScorer(), my_custom_scorer])

    This is useful when you want to guarantee that the highest individual risk
    signal is never diluted by averaging.
    """

    scorers: Sequence[Any]
    """Sequence of scorers satisfying the :class:`RiskScorer` protocol."""

    def __post_init__(self) -> None:
        if not self.scorers:
            raise ValueError("MaxRiskScorer requires at least one scorer")

    @property
    def name(self) -> str:
        """Scorer identifier."""
        names = ",".join(s.name for s in self.scorers)
        return f"max({names})"

    def score(self, ctx: ActionContext) -> float:
        """Return the maximum score across all child scorers."""
        return _clamp(max(s.score(ctx) for s in self.scorers))

    def assess(self, ctx: ActionContext) -> RiskAssessment:
        """Produce a :class:`RiskAssessment` recording each child's contribution."""
        best_score = 0.0
        best_scorer_name = ""
        factors: list[RiskFactor] = []

        for scorer in self.scorers:
            child_score = scorer.score(ctx)
            if child_score >= best_score:
                best_score = child_score
                best_scorer_name = scorer.name
            factors.append(RiskFactor(
                name=f"scorer:{scorer.name}",
                contribution=child_score,
                description=f"Score {child_score:.3f} from '{scorer.name}'",
            ))

        clamped = _clamp(best_score)
        return RiskAssessment(
            score=clamped,
            level=RiskLevel.from_score(clamped),
            factors=factors,
            scorer_name=f"max(winner={best_scorer_name})",
        )


# ---------------------------------------------------------------------------
# FixedRiskScorer
# ---------------------------------------------------------------------------

@dataclass
class FixedRiskScorer:
    """Always returns a fixed, pre-configured risk score.

    Useful for testing, explicit overrides, or as a floor / ceiling in a
    :class:`CompositeRiskScorer`.

    Example::

        scorer = FixedRiskScorer(0.9)  # always critical
    """

    fixed_score: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.fixed_score <= 1.0:
            raise ValueError(
                f"fixed_score must be in [0.0, 1.0], got {self.fixed_score}"
            )

    @property
    def name(self) -> str:
        """Scorer identifier."""
        return f"fixed({self.fixed_score:.2f})"

    def score(self, ctx: ActionContext) -> float:
        """Return the fixed score regardless of context."""
        return self.fixed_score

    def assess(self, ctx: ActionContext) -> RiskAssessment:
        """Produce a :class:`RiskAssessment` with a single explanatory factor."""
        return RiskAssessment(
            score=self.fixed_score,
            level=RiskLevel.from_score(self.fixed_score),
            factors=[
                RiskFactor(
                    name="fixed",
                    contribution=self.fixed_score,
                    description=f"Hardcoded risk score of {self.fixed_score:.2f}.",
                ),
            ],
            scorer_name=self.name,
        )
