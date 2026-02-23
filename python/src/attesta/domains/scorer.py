"""Domain-aware risk scorer for attesta-ai.

The :class:`DomainRiskScorer` wraps a base :class:`RiskScorer` implementation
and amplifies or adjusts the raw score using domain-specific knowledge from a
:class:`DomainProfile`.

Scoring pipeline
~~~~~~~~~~~~~~~~

1. **Base score** -- obtained from the wrapped scorer (defaults to
   :class:`DefaultRiskScorer` from :mod:`attesta.core.risk`).
2. **Pattern matching** -- domain :class:`RiskPattern` instances are matched
   against the function name, arguments, keyword arguments, and docstring.
   Matching patterns contribute additional risk via the maximum contribution
   across all matches (not a sum, to avoid run-away inflation).
3. **Sensitive terms** -- domain-specific terms found in stringified context
   boost the score.
4. **Critical / safe overrides** -- if the function name matches a
   ``critical_actions`` pattern the score is floored to 0.8; if it matches
   a ``safe_actions`` pattern the score is capped to 0.15.
5. **Base risk floor** -- the domain's ``base_risk_floor`` is applied.
6. **Production multiplier** -- if the environment is ``"production"`` the
   score is multiplied by ``production_multiplier``.
7. **Clamp** -- the final score is clamped to [0.0, 1.0].

The scorer satisfies the :class:`RiskScorer` protocol and can be used
anywhere a scorer is expected (e.g. passed to :class:`Attesta`).

Example::

    from attesta.core.risk import DefaultRiskScorer
    from attesta.domains.profile import DomainProfile, RiskPattern
    from attesta.domains.scorer import DomainRiskScorer

    profile = DomainProfile(
        name="my-domain",
        display_name="My Domain",
        description="Custom compliance profile for my domain.",
        risk_patterns=[
            RiskPattern(
                pattern=r"confidential|secret|restricted",
                target="any",
                risk_contribution=0.8,
                name="confidential_access",
                description="Access to confidential data.",
                compliance_refs=["SOC 2 CC6.1"],
            ),
        ],
        sensitive_terms={"confidential": 0.7, "secret": 0.9},
    )
    scorer = DomainRiskScorer(profile)
    score = scorer.score(ctx)
"""

from __future__ import annotations

import re
from typing import Any

from attesta.core.risk import DefaultRiskScorer
from attesta.core.types import (
    ActionContext,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
)
from attesta.domains.profile import (
    DomainProfile,
    EscalationRule,
    RiskPattern,
)

__all__ = ["DomainRiskScorer"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp *value* to the closed interval [lo, hi]."""
    return max(lo, min(hi, value))


def _stringify_args(args: tuple, kwargs: dict[str, Any]) -> tuple[str, str]:
    """Return stringified representations of positional and keyword args."""
    args_str = " ".join(str(a) for a in args) if args else ""
    kwargs_str = " ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
    return args_str, kwargs_str


# ---------------------------------------------------------------------------
# Escalation condition parser
# ---------------------------------------------------------------------------

class _ConditionEvaluator:
    """Evaluate simple escalation condition strings.

    Supported condition forms:

    * ``"risk_score > 0.9"``  -- numeric comparison (>, >=, <, <=, ==, !=)
    * ``"risk_score >= 0.85"``
    * ``"matches_pattern:pattern_name"`` -- true if the named pattern matched
    * ``"environment:production"`` -- true if the context environment matches
    * ``"risk_level:critical"`` -- true if the assessed risk level matches
    """

    _COMPARISON_RE = re.compile(
        r"^risk_score\s*(>=|<=|>|<|==|!=)\s*([0-9]*\.?[0-9]+)$"
    )

    @classmethod
    def evaluate(
        cls,
        condition: str,
        ctx: ActionContext,
        risk: RiskAssessment,
        matched_pattern_names: set[str],
    ) -> bool:
        """Evaluate a single condition string and return True if it fires."""
        condition = condition.strip()

        # risk_score comparison.
        m = cls._COMPARISON_RE.match(condition)
        if m:
            op, threshold_str = m.group(1), m.group(2)
            threshold = float(threshold_str)
            return cls._compare(risk.score, op, threshold)

        # matches_pattern:<name>
        if condition.startswith("matches_pattern:"):
            pattern_name = condition.split(":", 1)[1].strip()
            return pattern_name in matched_pattern_names

        # environment:<value>
        if condition.startswith("environment:"):
            env_value = condition.split(":", 1)[1].strip()
            return ctx.environment.lower() == env_value.lower()

        # risk_level:<level>
        if condition.startswith("risk_level:"):
            level_value = condition.split(":", 1)[1].strip()
            return risk.level.value.lower() == level_value.lower()

        # Unrecognised condition -- treat as non-matching (fail-open for
        # conditions, fail-safe for the overall system via other checks).
        return False

    @staticmethod
    def _compare(score: float, op: str, threshold: float) -> bool:
        """Perform a numeric comparison."""
        if op == ">":
            return score > threshold
        if op == ">=":
            return score >= threshold
        if op == "<":
            return score < threshold
        if op == "<=":
            return score <= threshold
        if op == "==":
            return abs(score - threshold) < 1e-9
        if op == "!=":
            return abs(score - threshold) >= 1e-9
        return False


# ---------------------------------------------------------------------------
# DomainRiskScorer
# ---------------------------------------------------------------------------

class DomainRiskScorer:
    """Risk scorer that uses domain knowledge to evaluate actions.

    Wraps a base scorer (default: :class:`DefaultRiskScorer`) and applies
    domain-specific amplification, pattern matching, and escalation logic
    from a :class:`DomainProfile`.

    This class satisfies the :class:`RiskScorer` protocol (``score(ctx)``
    and ``name`` property).
    """

    def __init__(
        self,
        profile: DomainProfile,
        base_scorer: Any | None = None,
    ) -> None:
        self.profile = profile
        self._base_scorer = base_scorer or DefaultRiskScorer()

    # -- Protocol properties -------------------------------------------------

    @property
    def name(self) -> str:
        """Scorer identifier used in :class:`RiskAssessment`."""
        return f"domain:{self.profile.name}"

    # -- Public API ----------------------------------------------------------

    def score(self, ctx: ActionContext) -> float:
        """Return a risk score in [0.0, 1.0] for the given action context.

        This is the lightweight entry point that satisfies the
        :class:`RiskScorer` protocol.  For full details including factor
        breakdowns and compliance references, use :meth:`assess`.
        """
        assessment = self.assess(ctx)
        return assessment.score

    def assess(self, ctx: ActionContext) -> RiskAssessment:
        """Produce a full :class:`RiskAssessment` with domain-specific factors.

        The assessment includes detailed :class:`RiskFactor` entries with
        compliance references and domain context for each contributing
        signal.
        """
        factors: list[RiskFactor] = []

        # ---- Step 1: Base score ----
        base_score = self._base_scorer.score(ctx)
        factors.append(RiskFactor(
            name="base_score",
            contribution=base_score,
            description=(
                f"Base risk score from '{self._base_scorer.name}' scorer."
            ),
            evidence=f"raw_score={base_score:.4f}",
        ))

        running_score = base_score

        # ---- Step 2: Domain risk patterns ----
        pattern_matches = self._match_patterns(ctx)
        if pattern_matches:
            max_pattern_contribution = max(c for _, c in pattern_matches)
            matched_names = [rp.name for rp, _ in pattern_matches]
            compliance_refs: list[str] = []
            for rp, _ in pattern_matches:
                compliance_refs.extend(rp.compliance_refs)

            ref_str = (
                f" Compliance: {', '.join(compliance_refs)}"
                if compliance_refs else ""
            )
            factors.append(RiskFactor(
                name="domain_patterns",
                contribution=max_pattern_contribution,
                description=(
                    f"Domain patterns matched: {', '.join(matched_names)}.{ref_str}"
                ),
                evidence="; ".join(
                    f"{rp.name} ({rp.description}, +{c:.3f})"
                    for rp, c in pattern_matches
                ),
            ))
            running_score = max(running_score, running_score + max_pattern_contribution * (1.0 - running_score))

        # ---- Step 3: Sensitive terms ----
        sensitive_score = self._score_sensitive_terms(ctx)
        if sensitive_score > 0.0:
            all_text = self._build_full_text(ctx)
            term_matches = self.profile.get_matching_sensitive_terms(all_text)
            term_evidence = "; ".join(
                f"'{pat}' weight={w:.2f}" for pat, w in term_matches
            )
            factors.append(RiskFactor(
                name="sensitive_terms",
                contribution=sensitive_score,
                description="Domain-sensitive terminology detected.",
                evidence=term_evidence or "sensitive terms found",
            ))
            # Blend the sensitive term score into the running score.
            running_score = max(
                running_score,
                running_score + sensitive_score * (1.0 - running_score),
            )

        # ---- Step 4: Critical / safe action overrides ----
        is_critical = self.profile.is_critical_action(ctx.function_name)
        is_safe = self.profile.is_safe_action(ctx.function_name)

        if is_critical:
            critical_floor = 0.8
            if running_score < critical_floor:
                factors.append(RiskFactor(
                    name="critical_action_override",
                    contribution=critical_floor - running_score,
                    description=(
                        f"Function '{ctx.function_name}' matches a domain "
                        f"critical action pattern.  Score floored to {critical_floor}."
                    ),
                    evidence=f"matched critical_actions in domain '{self.profile.name}'",
                ))
                running_score = critical_floor
            else:
                factors.append(RiskFactor(
                    name="critical_action_flag",
                    contribution=0.0,
                    description=(
                        f"Function '{ctx.function_name}' matches a domain "
                        f"critical action pattern (score already >= {critical_floor})."
                    ),
                    evidence=f"matched critical_actions in domain '{self.profile.name}'",
                ))
        elif is_safe:
            safe_cap = 0.15
            if running_score > safe_cap:
                reduction = running_score - safe_cap
                factors.append(RiskFactor(
                    name="safe_action_override",
                    contribution=-reduction,
                    description=(
                        f"Function '{ctx.function_name}' matches a domain "
                        f"safe action pattern.  Score capped to {safe_cap}."
                    ),
                    evidence=f"matched safe_actions in domain '{self.profile.name}'",
                ))
                running_score = safe_cap
            else:
                factors.append(RiskFactor(
                    name="safe_action_flag",
                    contribution=0.0,
                    description=(
                        f"Function '{ctx.function_name}' matches a domain "
                        f"safe action pattern (score already <= {safe_cap})."
                    ),
                    evidence=f"matched safe_actions in domain '{self.profile.name}'",
                ))

        # ---- Step 5: Base risk floor ----
        if self.profile.base_risk_floor > 0.0 and running_score < self.profile.base_risk_floor:
            floor_delta = self.profile.base_risk_floor - running_score
            factors.append(RiskFactor(
                name="domain_risk_floor",
                contribution=floor_delta,
                description=(
                    f"Domain '{self.profile.name}' enforces a base risk floor "
                    f"of {self.profile.base_risk_floor:.2f}."
                ),
                evidence=f"score {running_score:.4f} raised to {self.profile.base_risk_floor:.4f}",
            ))
            running_score = self.profile.base_risk_floor

        # ---- Step 6: Production multiplier ----
        if (
            ctx.environment.lower() == "production"
            and self.profile.production_multiplier != 1.0
        ):
            pre_multiplier = running_score
            running_score = running_score * self.profile.production_multiplier
            multiplier_delta = running_score - pre_multiplier
            factors.append(RiskFactor(
                name="production_multiplier",
                contribution=multiplier_delta,
                description=(
                    f"Production environment detected.  Score multiplied by "
                    f"{self.profile.production_multiplier:.2f}."
                ),
                evidence=(
                    f"pre={pre_multiplier:.4f} * {self.profile.production_multiplier:.2f} "
                    f"= {running_score:.4f}"
                ),
            ))

        # ---- Step 7: Clamp ----
        final_score = _clamp(running_score)

        return RiskAssessment(
            score=final_score,
            level=RiskLevel.from_score(final_score),
            factors=factors,
            scorer_name=self.name,
        )

    def check_escalation(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
    ) -> EscalationRule | None:
        """Check if any escalation rules trigger for this action.

        Returns the **first** matching :class:`EscalationRule`, or ``None``
        if no rules fire.  Rules are evaluated in the order they appear in
        the profile.
        """
        # Gather matched pattern names for condition evaluation.
        matched_names = self._get_matched_pattern_names(ctx)

        for rule in self.profile.escalation_rules:
            if _ConditionEvaluator.evaluate(
                rule.condition, ctx, risk, matched_names
            ):
                return rule
        return None

    def check_all_escalations(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
    ) -> list[EscalationRule]:
        """Return **all** escalation rules that trigger for this action."""
        matched_names = self._get_matched_pattern_names(ctx)
        return [
            rule
            for rule in self.profile.escalation_rules
            if _ConditionEvaluator.evaluate(
                rule.condition, ctx, risk, matched_names
            )
        ]

    # -- Internal helpers ----------------------------------------------------

    def _match_patterns(
        self, ctx: ActionContext
    ) -> list[tuple[RiskPattern, float]]:
        """Match all domain patterns against the action context.

        Returns a list of ``(pattern, weighted_contribution)`` tuples for
        every pattern that matched.
        """
        matches: list[tuple[RiskPattern, float]] = []

        for rp in self.profile.risk_patterns:
            texts = self._get_target_texts(ctx, rp.target)
            for text in texts:
                if not text:
                    continue
                if rp.compiled.search(text):
                    matches.append((rp, rp.risk_contribution))
                    break  # One match per pattern is sufficient.

        return matches

    def _get_matched_pattern_names(self, ctx: ActionContext) -> set[str]:
        """Return the set of pattern names that matched this context."""
        return {rp.name for rp, _ in self._match_patterns(ctx)}

    @staticmethod
    def _get_target_texts(ctx: ActionContext, target: str) -> list[str]:
        """Return the text fields to match a pattern against.

        For ``target="any"`` all available text sources are returned.
        """
        args_str, kwargs_str = _stringify_args(ctx.args, ctx.kwargs)

        target_map: dict[str, list[str]] = {
            "function_name": [ctx.function_name],
            "args": [args_str],
            "kwargs": [kwargs_str],
            "docstring": [ctx.function_doc or ""],
            "any": [
                ctx.function_name,
                args_str,
                kwargs_str,
                ctx.function_doc or "",
            ],
        }
        return target_map.get(target, [])

    def _score_sensitive_terms(self, ctx: ActionContext) -> float:
        """Compute a risk contribution from sensitive terms in the context.

        Scans the full text of the action context (function name, args,
        kwargs, docstring) for domain-sensitive terms and returns the
        maximum weight found.
        """
        full_text = self._build_full_text(ctx)
        if not full_text:
            return 0.0

        matches = self.profile.get_matching_sensitive_terms(full_text)
        if not matches:
            return 0.0

        # Use the maximum weight -- avoids run-away summation.
        return max(w for _, w in matches)

    @staticmethod
    def _build_full_text(ctx: ActionContext) -> str:
        """Build a single searchable string from all context fields."""
        parts: list[str] = [ctx.function_name]
        if ctx.args:
            parts.extend(str(a) for a in ctx.args)
        if ctx.kwargs:
            parts.extend(f"{k}={v}" for k, v in ctx.kwargs.items())
        if ctx.function_doc:
            parts.append(ctx.function_doc)
        return " ".join(parts)
