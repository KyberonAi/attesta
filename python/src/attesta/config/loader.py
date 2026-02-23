"""Configuration loader for Attesta."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attesta.core.types import ChallengeType, RiskLevel

logger = logging.getLogger("attesta")


def _clamp(score: float) -> float:
    """Clamp a score to [0.0, 1.0]."""
    return max(0.0, min(1.0, score))


def _level_score(level: RiskLevel) -> float:
    """Map a risk level to a representative score."""
    return {
        RiskLevel.LOW: 0.15,
        RiskLevel.MEDIUM: 0.45,
        RiskLevel.HIGH: 0.70,
        RiskLevel.CRITICAL: 0.90,
    }[level]


class _AmplifiedRiskScorer:
    """Decorator scorer that applies config-level regex score boosts."""

    def __init__(self, base_scorer: Any, amplifiers: list[dict[str, Any]]) -> None:
        self._base = base_scorer
        self._compiled: list[tuple[re.Pattern[str], float]] = []

        for amp in amplifiers:
            pattern = amp.get("pattern")
            boost = amp.get("boost")
            if not isinstance(pattern, str):
                logger.warning("Ignoring risk amplifier with non-string pattern: %r", amp)
                continue
            try:
                boost_val = float(boost)
            except (TypeError, ValueError):
                logger.warning("Ignoring risk amplifier with invalid boost: %r", amp)
                continue
            try:
                compiled = re.compile(pattern)
            except re.error:
                logger.warning("Ignoring risk amplifier with invalid regex: %r", pattern)
                continue
            self._compiled.append((compiled, boost_val))

    @property
    def name(self) -> str:
        return f"{self._base.name}+amplifiers"

    def score(self, ctx: Any) -> float:
        score = float(self._base.score(ctx))
        fn_name = str(getattr(ctx, "function_name", ""))
        for pattern, boost in self._compiled:
            if pattern.search(fn_name):
                score += boost
        return _clamp(score)


class _OverrideRiskScorer:
    """Decorator scorer that applies exact function-name risk overrides."""

    def __init__(self, base_scorer: Any, overrides: dict[str, str]) -> None:
        self._base = base_scorer
        self._overrides: dict[str, RiskLevel] = {}

        for action_name, level_value in overrides.items():
            key = str(action_name).strip()
            if not key:
                continue
            try:
                if isinstance(level_value, RiskLevel):
                    level = level_value
                else:
                    level = RiskLevel(str(level_value).strip().lower())
            except ValueError:
                logger.warning(
                    "Ignoring invalid risk override for %s: %r",
                    key,
                    level_value,
                )
                continue
            self._overrides[key] = level

    @property
    def name(self) -> str:
        return f"{self._base.name}+overrides"

    def score(self, ctx: Any) -> float:
        base_score = _clamp(float(self._base.score(ctx)))
        fn_name = str(getattr(ctx, "function_name", ""))
        override = self._overrides.get(fn_name)
        if override is None and "." in fn_name:
            # Support configs that use bare function names while context uses qualname.
            override = self._overrides.get(fn_name.split(".")[-1])
        if override is not None:
            return _level_score(override)
        return base_score


@dataclass
class Policy:
    """Defines how risk levels map to verification requirements.

    Usage:
        policy = Policy()  # sensible defaults

        policy = Policy(
            auto_approve=RiskLevel.LOW,
            confirm=RiskLevel.MEDIUM,
            challenge=RiskLevel.HIGH,
            teach_back=RiskLevel.CRITICAL,
        )
    """
    # Which risk levels get which challenge type
    auto_approve: RiskLevel = RiskLevel.LOW
    confirm: RiskLevel = RiskLevel.MEDIUM
    challenge: RiskLevel = RiskLevel.HIGH
    teach_back: RiskLevel = RiskLevel.CRITICAL

    # Minimum review times (seconds) per risk level
    minimum_review_seconds: dict[str, float] = field(default_factory=lambda: {
        "low": 0,
        "medium": 3,
        "high": 10,
        "critical": 30,
    })

    # Multi-party requirements
    require_multi_party: dict[str, int] = field(default_factory=lambda: {
        "critical": 2,
    })

    # Trust engine settings
    trust_influence: float = 0.3
    trust_ceiling: float = 0.9
    trust_initial: float = 0.3
    trust_decay_rate: float = 0.01

    # Safety settings
    critical_always_verify: bool = True  # Trust NEVER bypasses CRITICAL
    fail_mode: str = "deny"  # "deny" | "allow" | "escalate"
    timeout_seconds: float = 300

    # Risk overrides: map action names/patterns to explicit risk levels
    risk_overrides: dict[str, str] = field(default_factory=dict)

    # Risk amplifiers: patterns that boost risk
    risk_amplifiers: list[dict[str, Any]] = field(default_factory=list)

    # Domain profile name(s) — preset name or list of names to merge.
    # Register presets with attesta.domains.presets.register_preset()
    # before loading config, or create DomainProfile instances directly.
    domain: str | list[str] | None = None

    # When True, missing domain profiles raise an error instead of
    # logging a warning and falling back to no domain scoring.
    # OSS default is fail-fast to prevent silent misconfiguration.
    domain_strict: bool = True

    # Audit backend: "legacy" (default) or "trailproof"
    audit_backend: str = "legacy"
    audit_path: str = ".attesta/audit.jsonl"
    audit_tenant_id: str = "default"
    audit_hmac_key: str | None = None

    # Custom challenge map overrides: risk level name -> challenge type name.
    # Parsed from YAML ``policy.challenge_map``.  When absent,
    # :meth:`challenge_for_risk` falls back to built-in defaults.
    challenge_map_overrides: dict[str, str] = field(default_factory=dict)

    # Canonical token lookup (accepts both snake_case and kebab-case)
    _CHALLENGE_ALIASES: dict[str, ChallengeType] = field(
        default_factory=lambda: {
            "auto_approve": ChallengeType.AUTO_APPROVE,
            "auto-approve": ChallengeType.AUTO_APPROVE,
            "confirm": ChallengeType.CONFIRM,
            "quiz": ChallengeType.QUIZ,
            "teach_back": ChallengeType.TEACH_BACK,
            "teach-back": ChallengeType.TEACH_BACK,
            "multi_party": ChallengeType.MULTI_PARTY,
            "multi-party": ChallengeType.MULTI_PARTY,
        },
        repr=False,
    )

    def __post_init__(self) -> None:
        self.fail_mode = str(self.fail_mode).strip().lower()
        if self.fail_mode not in {"deny", "allow", "escalate"}:
            raise ValueError(
                "policy.fail_mode must be one of: deny, allow, escalate"
            )
        self.timeout_seconds = float(self.timeout_seconds)
        if self.timeout_seconds <= 0:
            raise ValueError("policy.timeout_seconds must be > 0")

    def challenge_for_risk(self, level: RiskLevel) -> ChallengeType:
        """Determine which challenge type to use for a given risk level.

        If a ``challenge_map`` was provided via YAML config, its entries
        take precedence.  Otherwise the built-in defaults are used.
        """
        # Check user-provided override first
        override = self.challenge_map_overrides.get(level.value)
        if override is not None:
            ct = self._CHALLENGE_ALIASES.get(override.lower())
            if ct is not None:
                return ct
            import logging
            logging.getLogger("attesta").warning(
                "Unknown challenge type '%s' in challenge_map for %s; "
                "using default.",
                override,
                level.value,
            )

        # Built-in defaults
        if level == RiskLevel.LOW:
            return ChallengeType.AUTO_APPROVE
        elif level == RiskLevel.MEDIUM:
            return ChallengeType.CONFIRM
        elif level == RiskLevel.HIGH:
            return ChallengeType.QUIZ
        else:  # CRITICAL
            parties = self.require_multi_party.get("critical", 1)
            if parties > 1:
                return ChallengeType.MULTI_PARTY
            return ChallengeType.TEACH_BACK

    def min_review_time(self, level: RiskLevel) -> float:
        """Get minimum review time for a risk level."""
        return self.minimum_review_seconds.get(level.value, 0)

    def to_challenge_map(self) -> dict[RiskLevel, ChallengeType]:
        """Build a complete challenge map from this policy's settings.

        Returns a mapping from every :class:`RiskLevel` to the
        :class:`ChallengeType` determined by :meth:`challenge_for_risk`.
        """
        return {level: self.challenge_for_risk(level) for level in RiskLevel}

    def build_risk_scorer(self) -> Any | None:
        """Build a domain-aware risk scorer if a domain is configured.

        Returns a :class:`~attesta.domains.scorer.DomainRiskScorer` wrapping
        the appropriate domain profile(s), optionally layered with config
        amplifiers/overrides. Returns ``None`` when no scorer customization
        is needed.

        Domain profiles can be loaded from:

        1. **Registered presets** -- call
           :func:`~attesta.domains.presets.register_preset` before loading
           the config.
        2. **The global registry** -- register profiles with
           :data:`~attesta.domains.profile.registry` before loading.

        When multiple domain names are provided (list), the profiles are
        merged via :meth:`~attesta.domains.profile.DomainRegistry.merge`
        to produce a composite profile.
        """
        from attesta.core.risk import DefaultRiskScorer
        from attesta.domains.presets import load_preset
        from attesta.domains.scorer import DomainRiskScorer

        scorer: Any | None = None

        try:
            if self.domain is not None:
                if isinstance(self.domain, str):
                    profile = load_preset(self.domain)
                    scorer = DomainRiskScorer(profile)
                elif isinstance(self.domain, list) and len(self.domain) == 1:
                    profile = load_preset(self.domain[0])
                    scorer = DomainRiskScorer(profile)
                elif isinstance(self.domain, list) and len(self.domain) > 1:
                    from attesta.domains.profile import DomainRegistry

                    profiles = [load_preset(name) for name in self.domain]
                    registry = DomainRegistry()
                    for p in profiles:
                        registry.register(p)
                    merged = registry.merge(*profiles)
                    scorer = DomainRiskScorer(merged)
        except KeyError as exc:
            if self.domain_strict:
                raise
            logger.warning(
                "Domain profile '%s' not found.  Register presets with "
                "attesta.domains.presets.register_preset() or create a "
                "DomainProfile directly.  Error: %s",
                self.domain,
                exc,
            )

        # If no domain scorer was configured, only build a base scorer when
        # risk-level overrides or amplifiers are explicitly configured.
        if scorer is None:
            if not self.risk_overrides and not self.risk_amplifiers:
                return None
            scorer = DefaultRiskScorer()

        # Evaluation order: base/domain scorer -> amplifiers -> overrides.
        if self.risk_amplifiers:
            scorer = _AmplifiedRiskScorer(scorer, self.risk_amplifiers)
        if self.risk_overrides:
            scorer = _OverrideRiskScorer(scorer, self.risk_overrides)
        return scorer

    def to_trust_engine_kwargs(self) -> dict[str, Any]:
        """Return the trust-related settings as a dict suitable for
        constructing a :class:`~attesta.core.trust.TrustEngine`.

        Keys returned: ``initial_score``, ``ceiling``, ``decay_rate``,
        ``influence``.
        """
        return {
            "initial_score": self.trust_initial,
            "ceiling": self.trust_ceiling,
            "decay_rate": self.trust_decay_rate,
            "influence": self.trust_influence,
        }


def load_config(path: str | Path = "attesta.yaml") -> Policy:
    """Load a Policy from a YAML configuration file.

    Supports both YAML and TOML formats.
    Falls back to defaults if file not found.
    """
    path = Path(path)

    if not path.exists():
        return Policy()

    suffix = path.suffix.lower()

    if suffix in (".yaml", ".yml"):
        return _load_yaml(path)
    elif suffix == ".toml":
        return _load_toml(path)
    else:
        raise ValueError(f"Unsupported config format: {suffix}. Use .yaml or .toml")


def _load_yaml(path: Path) -> Policy:
    """Load config from YAML file."""
    try:
        import yaml
    except ImportError as err:
        raise ImportError("PyYAML is required to load YAML config. Install with: pip install attesta[yaml]") from err

    data = yaml.safe_load(path.read_text())
    return _parse_config(data)


def _load_toml(path: Path) -> Policy:
    """Load config from TOML file."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError as err:
            raise ImportError("tomli is required for Python <3.11 TOML support") from err

    data = tomllib.loads(path.read_text())
    return _parse_config(data)


def _parse_config(data: dict) -> Policy:
    """Parse configuration dictionary into a Policy."""
    if not data:
        return Policy()

    policy_data = data.get("policy", {})
    risk_data = data.get("risk", {})
    trust_data = data.get("trust", {})

    kwargs: dict[str, Any] = {}

    # Parse minimum review times
    if "minimum_review_seconds" in policy_data:
        kwargs["minimum_review_seconds"] = policy_data["minimum_review_seconds"]

    # Parse multi-party requirements
    if "require_multi_party" in policy_data:
        kwargs["require_multi_party"] = policy_data["require_multi_party"]

    # Parse challenge_map overrides (risk level -> challenge type string)
    challenge_map_raw = policy_data.get("challenge_map") or policy_data.get("challenges")
    if challenge_map_raw and isinstance(challenge_map_raw, dict):
        kwargs["challenge_map_overrides"] = {
            k.lower(): str(v) for k, v in challenge_map_raw.items()
        }

    # Parse trust settings
    if trust_data:
        if "influence" in trust_data:
            kwargs["trust_influence"] = trust_data["influence"]
        if "ceiling" in trust_data:
            kwargs["trust_ceiling"] = trust_data["ceiling"]
        if "initial_score" in trust_data:
            kwargs["trust_initial"] = trust_data["initial_score"]
        if "decay_rate" in trust_data:
            kwargs["trust_decay_rate"] = trust_data["decay_rate"]

    # Parse risk overrides
    if "overrides" in risk_data:
        kwargs["risk_overrides"] = risk_data["overrides"]

    # Parse risk amplifiers
    if "amplifiers" in risk_data:
        kwargs["risk_amplifiers"] = risk_data["amplifiers"]

    # Parse safety settings
    if "fail_mode" in policy_data:
        kwargs["fail_mode"] = policy_data["fail_mode"]
    if "timeout_seconds" in policy_data:
        kwargs["timeout_seconds"] = policy_data["timeout_seconds"]

    # Parse domain profile
    domain_value = data.get("domain")
    if domain_value is not None:
        kwargs["domain"] = domain_value

    # Parse domain_strict (fail-fast if domain preset is missing)
    domain_strict = data.get("domain_strict")
    if domain_strict is not None:
        kwargs["domain_strict"] = bool(domain_strict)

    # Parse audit backend settings
    audit_data = data.get("audit", {})
    if isinstance(audit_data, dict):
        if "backend" in audit_data:
            kwargs["audit_backend"] = str(audit_data["backend"]).strip().lower()
        if "path" in audit_data:
            kwargs["audit_path"] = str(audit_data["path"])
        if "tenant_id" in audit_data:
            kwargs["audit_tenant_id"] = str(audit_data["tenant_id"])
        if "hmac_key" in audit_data:
            kwargs["audit_hmac_key"] = str(audit_data["hmac_key"])

    return Policy(**kwargs)
