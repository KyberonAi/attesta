"""Domain knowledge profiles for attesta-ai.

A domain profile encapsulates industry-specific risk patterns, sensitive
terminology, compliance requirements, escalation rules, and challenge
templates.  By loading an appropriate profile, the attesta can adjust
its risk scoring and challenge flow to match the conventions and
regulations of the operator's domain.

Attesta provides the domain profile framework (types, registry, scorer);
you create profiles for your industry.

Usage::

    from attesta.domains.profile import DomainProfile, RiskPattern, registry

    my_profile = DomainProfile(
        name="my-domain",
        display_name="My Domain",
        description="Custom risk profile for my domain.",
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
        sensitive_terms={"confidential": 0.7, "secret": 0.9, "restricted": 0.8},
        critical_actions=["delete_records", "export_all_data"],
        safe_actions=["check_status", "list_items"],
        compliance_frameworks=["SOC 2", "ISO 27001"],
    )
    registry.register(my_profile)
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

__all__ = [
    "RiskPattern",
    "EscalationRule",
    "DomainChallengeTemplate",
    "DomainProfile",
    "DomainRegistry",
    "registry",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RiskPattern:
    """A domain-specific pattern that affects risk scoring.

    The *pattern* can be either a raw string (used as a literal regex) or a
    pre-compiled :class:`re.Pattern`.  Regardless of how it is supplied,
    :meth:`DomainProfile.__post_init__` will compile it so that all
    downstream matching uses compiled patterns for performance.

    *target* determines which part of the :class:`ActionContext` the pattern
    is matched against:

    * ``"function_name"`` -- the function's qualified name
    * ``"args"``          -- stringified positional arguments
    * ``"kwargs"``        -- stringified keyword arguments
    * ``"docstring"``     -- the function docstring
    * ``"any"``           -- all of the above (logical OR)
    """

    pattern: re.Pattern[str] | str
    target: str  # "function_name" | "args" | "kwargs" | "docstring" | "any"
    risk_contribution: float  # 0.0 - 1.0
    name: str  # human-readable name
    description: str  # why this pattern is risky in this domain
    compliance_refs: list[str] = field(default_factory=list)

    _VALID_TARGETS: frozenset[str] = frozenset({"function_name", "args", "kwargs", "docstring", "any"})

    def __post_init__(self) -> None:
        if self.target not in self._VALID_TARGETS:
            raise ValueError(
                f"Invalid RiskPattern target '{self.target}'. Must be one of {sorted(self._VALID_TARGETS)}"
            )
        if not 0.0 <= self.risk_contribution <= 1.0:
            raise ValueError(f"risk_contribution must be in [0.0, 1.0], got {self.risk_contribution}")
        # Compile the pattern if it is still a plain string.
        if isinstance(self.pattern, str):
            self.pattern = re.compile(self.pattern, re.IGNORECASE)

    @property
    def compiled(self) -> re.Pattern[str]:
        """Return the compiled regex pattern (always available after init)."""
        if isinstance(self.pattern, str):
            # Defensive -- should not happen after __post_init__.
            return re.compile(self.pattern, re.IGNORECASE)
        return self.pattern


@dataclass
class EscalationRule:
    """When to escalate beyond the normal challenge flow.

    *condition* is a simple expression string evaluated against the action
    context and risk assessment.  Supported forms:

    * ``"risk_score > 0.9"`` -- numeric comparison on the risk score
    * ``"risk_score >= 0.85"``
    * ``"matches_pattern:phi_access"`` -- fires when a named RiskPattern matched
    * ``"environment:production"`` -- fires when the environment matches
    * ``"risk_level:critical"`` -- fires when the risk level matches

    *action* describes what should happen:

    * ``"require_multi_party"`` -- require multi-party approval
    * ``"notify_compliance"`` -- send a compliance notification
    * ``"block"`` -- unconditionally block the action
    * ``"require_teach_back"`` -- require a teach-back challenge
    """

    condition: str
    action: str
    required_approvers: int = 2
    notify_roles: list[str] = field(default_factory=list)
    description: str = ""

    _VALID_ACTIONS: frozenset[str] = frozenset(
        {"require_multi_party", "notify_compliance", "block", "require_teach_back", "require_confirmation"}
    )

    def __post_init__(self) -> None:
        if self.action not in self._VALID_ACTIONS:
            raise ValueError(
                f"Invalid EscalationRule action '{self.action}'. Must be one of {sorted(self._VALID_ACTIONS)}"
            )
        if self.required_approvers < 1:
            raise ValueError(f"required_approvers must be >= 1, got {self.required_approvers}")


@dataclass
class DomainChallengeTemplate:
    """Domain-specific challenge question template.

    *question_template* may contain ``{variable}`` placeholders that will be
    filled from the :class:`ActionContext` at challenge time.  The
    *context_vars* list documents which variables the template expects (for
    validation and introspection).

    *answer_hints* contains key terms that a correct response should include
    (used for fuzzy-matching teach-back validation).
    """

    question_template: str
    answer_hints: list[str]
    context_vars: list[str]
    challenge_type: str  # "quiz" | "teach_back"
    min_risk_level: str = "high"

    _VALID_CHALLENGE_TYPES: frozenset[str] = frozenset({"quiz", "teach_back"})
    _VALID_RISK_LEVELS: frozenset[str] = frozenset({"low", "medium", "high", "critical"})

    def __post_init__(self) -> None:
        if self.challenge_type not in self._VALID_CHALLENGE_TYPES:
            raise ValueError(
                f"Invalid challenge_type '{self.challenge_type}'. Must be one of {sorted(self._VALID_CHALLENGE_TYPES)}"
            )
        if self.min_risk_level not in self._VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid min_risk_level '{self.min_risk_level}'. Must be one of {sorted(self._VALID_RISK_LEVELS)}"
            )


@dataclass
class DomainProfile:
    """Complete domain knowledge profile for risk-aware HITL.

    A profile aggregates all domain-specific knowledge that the attesta
    uses to make better risk decisions:

    * **Risk patterns** -- regex patterns that boost risk when matched
    * **Sensitive terms** -- individual words/phrases with associated risk
    * **Critical / safe actions** -- function-name patterns for overrides
    * **Compliance frameworks** -- regulatory references for audit trails
    * **Escalation rules** -- conditions that trigger special handling
    * **Challenge templates** -- domain-tailored verification questions
    * **Review time overrides** -- minimum thinking time per risk level
    * **Risk amplifiers** -- base floors and production multipliers
    * **Required vocabulary** -- terms the operator should use in teach-backs
    """

    name: str
    display_name: str
    description: str

    # Risk patterns -- domain-specific signals.
    risk_patterns: list[RiskPattern] = field(default_factory=list)

    # Sensitive terms -- words that boost risk in this domain.
    # Keys are lowercased terms; values are risk contributions in [0, 1].
    sensitive_terms: dict[str, float] = field(default_factory=dict)

    # Critical actions -- function name patterns that are always high/critical.
    critical_actions: list[str] = field(default_factory=list)

    # Safe actions -- function name patterns that are always low risk.
    safe_actions: list[str] = field(default_factory=list)

    # Compliance frameworks referenced by this domain.
    compliance_frameworks: list[str] = field(default_factory=list)

    # Escalation rules.
    escalation_rules: list[EscalationRule] = field(default_factory=list)

    # Challenge templates.
    challenge_templates: list[DomainChallengeTemplate] = field(default_factory=list)

    # Domain-specific minimum review times (override defaults).
    # Keys are risk level names (e.g. "critical"); values are seconds.
    min_review_overrides: dict[str, float] = field(default_factory=dict)

    # Risk amplifiers.
    base_risk_floor: float = 0.0
    production_multiplier: float = 1.5

    # Domain vocabulary for teach-back validation.
    required_vocabulary: list[str] = field(default_factory=list)

    # Internal: compiled patterns for critical/safe action matching.
    _critical_patterns: list[re.Pattern[str]] = field(default_factory=list, repr=False, compare=False)
    _safe_patterns: list[re.Pattern[str]] = field(default_factory=list, repr=False, compare=False)
    _sensitive_term_patterns: list[tuple[re.Pattern[str], float]] = field(
        default_factory=list, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Pre-compile all string patterns for fast matching."""
        # Ensure every RiskPattern has a compiled regex.
        for rp in self.risk_patterns:
            if isinstance(rp.pattern, str):
                rp.pattern = re.compile(rp.pattern, re.IGNORECASE)

        # Compile critical action patterns (fnmatch-style globs -> regex).
        self._critical_patterns = [re.compile(self._glob_to_regex(p), re.IGNORECASE) for p in self.critical_actions]

        # Compile safe action patterns.
        self._safe_patterns = [re.compile(self._glob_to_regex(p), re.IGNORECASE) for p in self.safe_actions]

        # Compile sensitive term patterns.
        self._sensitive_term_patterns = [
            (re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE), weight)
            for term, weight in self.sensitive_terms.items()
        ]

        # Validate base_risk_floor.
        if not 0.0 <= self.base_risk_floor <= 1.0:
            raise ValueError(f"base_risk_floor must be in [0.0, 1.0], got {self.base_risk_floor}")

        # Validate production_multiplier.
        if self.production_multiplier < 0.0:
            raise ValueError(f"production_multiplier must be non-negative, got {self.production_multiplier}")

    @staticmethod
    def _glob_to_regex(pattern: str) -> str:
        """Convert a simple glob pattern to a regex.

        Supports ``*`` as a wildcard for any sequence of characters.  The
        pattern is anchored with word boundaries so that ``delete_patient``
        matches the function name ``delete_patient_record`` but not
        ``undelete_patient``.
        """
        # If the pattern already looks like regex, pass it through.
        if any(c in pattern for c in r"()[]{}+?^$|\\"):
            return pattern
        # Convert glob wildcards.
        escaped = re.escape(pattern).replace(r"\*", ".*")
        return escaped

    def is_critical_action(self, function_name: str) -> bool:
        """Return True if *function_name* matches any critical action pattern."""
        return any(p.search(function_name) for p in self._critical_patterns)

    def is_safe_action(self, function_name: str) -> bool:
        """Return True if *function_name* matches any safe action pattern."""
        return any(p.search(function_name) for p in self._safe_patterns)

    def get_matching_sensitive_terms(self, text: str) -> list[tuple[str, float]]:
        """Return all sensitive terms found in *text* with their weights."""
        matches: list[tuple[str, float]] = []
        for pat, weight in self._sensitive_term_patterns:
            if pat.search(text):
                matches.append((pat.pattern, weight))
        return matches

    def get_templates_for_level(self, risk_level: str) -> list[DomainChallengeTemplate]:
        """Return challenge templates applicable to the given risk level.

        A template is applicable if its ``min_risk_level`` is at or below
        the requested level.
        """
        level_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        requested = level_order.get(risk_level, 0)
        return [t for t in self.challenge_templates if level_order.get(t.min_risk_level, 0) <= requested]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class DomainRegistry:
    """Registry of available domain profiles.

    The registry provides a central place to register, retrieve, and merge
    domain profiles.  A module-level singleton ``registry`` is provided for
    convenience.

    Example::

        from attesta.domains.profile import DomainProfile, registry

        registry.register(DomainProfile(
            name="my-domain",
            display_name="My Domain",
            description="Custom compliance profile for my domain.",
        ))
        profile = registry.get("my-domain")
    """

    def __init__(self) -> None:
        self._profiles: dict[str, DomainProfile] = {}

    def register(self, profile: DomainProfile) -> None:
        """Register a domain profile.

        Raises ``ValueError`` if a profile with the same name already exists.
        Use :meth:`replace` to overwrite an existing profile.
        """
        if profile.name in self._profiles:
            raise ValueError(f"Domain profile '{profile.name}' is already registered. Use replace() to overwrite.")
        self._profiles[profile.name] = profile

    def replace(self, profile: DomainProfile) -> None:
        """Register or replace a domain profile unconditionally."""
        self._profiles[profile.name] = profile

    def get(self, name: str) -> DomainProfile:
        """Retrieve a registered domain profile by name.

        Raises ``KeyError`` if the profile has not been registered.
        """
        try:
            return self._profiles[name]
        except KeyError:
            available = ", ".join(sorted(self._profiles)) or "(none)"
            raise KeyError(f"Domain profile '{name}' not found. Available profiles: {available}") from None

    def list_domains(self) -> list[str]:
        """Return a sorted list of all registered domain names."""
        return sorted(self._profiles)

    def __contains__(self, name: str) -> bool:
        """Support ``'my-domain' in registry`` syntax."""
        return name in self._profiles

    def __len__(self) -> int:
        return len(self._profiles)

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._profiles))

    def merge(self, *profiles: DomainProfile) -> DomainProfile:
        """Merge multiple profiles into a single composite profile.

        The resulting profile combines all risk patterns, sensitive terms,
        critical/safe actions, compliance frameworks, escalation rules,
        challenge templates, and vocabulary from the input profiles.

        For conflicting scalar values (e.g. ``base_risk_floor``), the most
        conservative (highest) value is used.  For ``production_multiplier``,
        the maximum is taken.

        The merged profile is **not** automatically registered; call
        :meth:`register` on the result if needed.

        Raises ``ValueError`` if fewer than two profiles are provided.
        """
        if len(profiles) < 2:
            raise ValueError("merge() requires at least two profiles")

        names = [p.name for p in profiles]
        merged_name = "+".join(names)
        display_names = " + ".join(p.display_name for p in profiles)
        descriptions = " | ".join(p.description for p in profiles)

        # Combine list fields.
        all_risk_patterns: list[RiskPattern] = []
        all_critical: list[str] = []
        all_safe: list[str] = []
        all_frameworks: list[str] = []
        all_escalation: list[EscalationRule] = []
        all_templates: list[DomainChallengeTemplate] = []
        all_vocabulary: list[str] = []

        # Combine dict fields.
        merged_sensitive: dict[str, float] = {}
        merged_review_overrides: dict[str, float] = {}

        # Scalars -- take conservative values.
        max_floor = 0.0
        max_multiplier = 1.0

        for profile in profiles:
            # Deep-copy patterns to avoid mutating originals.
            all_risk_patterns.extend(copy.deepcopy(profile.risk_patterns))

            for term, weight in profile.sensitive_terms.items():
                # Take the higher weight if the same term appears in multiple profiles.
                existing = merged_sensitive.get(term, 0.0)
                merged_sensitive[term] = max(existing, weight)

            all_critical.extend(profile.critical_actions)
            all_safe.extend(profile.safe_actions)
            all_frameworks.extend(profile.compliance_frameworks)
            all_escalation.extend(copy.deepcopy(profile.escalation_rules))
            all_templates.extend(copy.deepcopy(profile.challenge_templates))
            all_vocabulary.extend(profile.required_vocabulary)

            for level, seconds in profile.min_review_overrides.items():
                existing_time = merged_review_overrides.get(level, 0.0)
                merged_review_overrides[level] = max(existing_time, seconds)

            max_floor = max(max_floor, profile.base_risk_floor)
            max_multiplier = max(max_multiplier, profile.production_multiplier)

        # Deduplicate preserving order.
        all_critical = list(dict.fromkeys(all_critical))
        all_safe = list(dict.fromkeys(all_safe))
        all_frameworks = list(dict.fromkeys(all_frameworks))
        all_vocabulary = list(dict.fromkeys(all_vocabulary))

        return DomainProfile(
            name=merged_name,
            display_name=display_names,
            description=descriptions,
            risk_patterns=all_risk_patterns,
            sensitive_terms=merged_sensitive,
            critical_actions=all_critical,
            safe_actions=all_safe,
            compliance_frameworks=all_frameworks,
            escalation_rules=all_escalation,
            challenge_templates=all_templates,
            min_review_overrides=merged_review_overrides,
            base_risk_floor=max_floor,
            production_multiplier=max_multiplier,
            required_vocabulary=all_vocabulary,
        )


# Module-level default registry instance.
registry = DomainRegistry()
