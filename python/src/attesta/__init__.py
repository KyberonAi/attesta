"""attesta-ai -- lightweight human-in-the-loop approval for AI agents.

Quick start::

    from attesta import gate

    @gate
    def deploy(service: str, version: str) -> None:
        ...

For richer configuration use the :class:`Attesta` entry point::

    from attesta import Attesta

    attesta = Attesta.from_config("attesta.yaml")

    @attesta.gate(risk_hints={"production": True})
    def deploy(service: str, version: str) -> None:
        ...
"""

from __future__ import annotations

import asyncio
import functools
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, TypeVar

if TYPE_CHECKING:
    from attesta.core.trust import TrustEngine as _TrustEngine

from attesta.core.gate import Attesta as CoreAttesta, AttestaDenied, gate
from attesta.core.types import (
    ActionContext,
    ApprovalResult,
    AuditLogger,
    ChallengeProtocol,
    ChallengeResult,
    ChallengeType,
    Renderer,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    RiskScorer,
    TeachBackValidator,
    Verdict,
)
from attesta.environment import Environment, detect_environment
from attesta.events import Event, EventBus, EventType
from attesta.exporters import CSVExporter, JSONExporter
from attesta.webhooks import WebhookConfig, WebhookDispatcher

__version__ = "0.1.0"

__all__ = [
    # Top-level convenience
    "Attesta",
    "gate",
    "__version__",
    # Core orchestrator
    "CoreAttesta",
    "AttestaDenied",
    # Enums
    "ChallengeType",
    "RiskLevel",
    "Verdict",
    # Data classes
    "ActionContext",
    "ApprovalResult",
    "ChallengeResult",
    "RiskAssessment",
    "RiskFactor",
    # Protocols
    "AuditLogger",
    "ChallengeProtocol",
    "Renderer",
    "RiskScorer",
    "TeachBackValidator",
    # Events
    "Event",
    "EventBus",
    "EventType",
    # Environment
    "Environment",
    "detect_environment",
    # Exporters
    "CSVExporter",
    "JSONExporter",
    # Webhooks
    "WebhookConfig",
    "WebhookDispatcher",
]

logger = logging.getLogger("attesta")

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Attesta -- the recommended high-level entry point
# ---------------------------------------------------------------------------

class Attesta:
    """Central configuration object for attesta-ai.

    Holds shared defaults (risk scorer, renderer, audit logger, policy) that
    are applied to every ``@attesta.gate()`` decorator created from this instance.

    Parameters
    ----------
    policy:
        A mapping of configuration options (typically loaded from YAML).
        Recognised keys:

        * ``default_environment`` -- default environment tag (str).
        * ``min_review_seconds`` -- minimum review wall-clock time (float).
        * ``challenge_map`` -- mapping from risk level name to challenge type
          name, e.g. ``{"low": "auto_approve", "high": "quiz"}``.
        * ``fail_mode`` -- timeout policy: ``deny``, ``allow``, or ``escalate``.
        * ``timeout_seconds`` -- max seconds to wait for challenge completion.

    risk_scorer:
        Default risk scorer for all gates.
    renderer:
        Default renderer for all gates.
    audit_logger:
        Default audit logger for all gates.
    trust_engine:
        Optional :class:`~attesta.core.trust.TrustEngine` (or compatible)
        for adaptive risk adjustment.  When provided, it is passed to each
        :class:`~attesta.core.gate.Attesta` which adjusts risk based on agent
        trust and records outcomes after evaluation.
    allow_hint_override:
        Whether to honour ``ctx.hints["risk_override"]`` at runtime.
        Defaults to ``False`` for safety. Set explicitly to ``True`` only
        when hints are controlled by trusted server-side code.
    """

    def __init__(
        self,
        *,
        policy: dict[str, Any] | None = None,
        risk_scorer: RiskScorer | None = None,
        renderer: Renderer | None = None,
        audit_logger: AuditLogger | None = None,
        trust_engine: _TrustEngine | None = None,
        event_bus: EventBus | None = None,
        allow_hint_override: bool | None = None,
        fail_mode: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self._policy: dict[str, Any] = dict(policy or {})
        self._risk_scorer = risk_scorer
        self._renderer = renderer
        self._audit_logger = audit_logger
        self._trust_engine: _TrustEngine | None = trust_engine
        self._event_bus: EventBus | None = event_bus
        if allow_hint_override is None:
            self._allow_hint_override = bool(
                self._policy.get("allow_hint_override", False)
            )
        else:
            self._allow_hint_override = bool(allow_hint_override)
        self._fail_mode = str(fail_mode or self._policy.get("fail_mode", "deny"))
        self._timeout_seconds = float(
            timeout_seconds
            if timeout_seconds is not None
            else self._policy.get("timeout_seconds", 600.0)
        )
        self._core_instance: CoreAttesta | None = None
        self._policy_obj: Any | None = None  # stores Policy for introspection

        # Pre-parse the challenge map from the policy if present.
        # Support both "challenge_map" and "challenges" (README uses "challenges").
        raw_map = self._policy.get("challenge_map") or self._policy.get(
            "challenges"
        )
        self._challenge_map = self._parse_challenge_map(raw_map)

    # -- public API --------------------------------------------------------

    async def evaluate(self, ctx: ActionContext) -> ApprovalResult:
        """Run the full gate flow for *ctx* and return the result.

        This is the primary entry point used by framework integrations.
        It uses a cached :class:`~attesta.core.gate.Attesta` instance
        to preserve stateful components like novelty tracking.

        Parameters
        ----------
        ctx:
            An :class:`ActionContext` describing the action under review.

        Returns
        -------
        ApprovalResult
            The full audit-ready approval record.
        """
        if self._core_instance is None:
            from attesta.core.gate import Attesta as _CoreAttesta

            self._core_instance = _CoreAttesta(
                risk_scorer=self._risk_scorer,
                renderer=self._renderer,
                audit_logger=self._audit_logger,
                challenge_map=self._challenge_map,
                min_review_seconds=self._policy.get("min_review_seconds", 0.0),
                trust_engine=self._trust_engine,
                event_bus=self._event_bus,
                allow_hint_override=self._allow_hint_override,
                fail_mode=self._fail_mode,
                approval_timeout_seconds=self._timeout_seconds,
            )
        return await self._core_instance.evaluate(ctx)

    @classmethod
    def from_config(cls, path: str | Path) -> Attesta:
        """Load configuration from a YAML file.

        If the file contains structured sections (``policy:``, ``risk:``,
        ``trust:``), the rich :class:`~attesta.config.loader.Policy`
        dataclass is used to derive challenge maps, minimum review times,
        and trust engine settings.

        For simple flat config dicts (legacy format) without those
        sections, the previous behaviour is preserved -- the raw dict is
        passed through as the ``policy`` parameter.

        .. code-block:: yaml

            # Rich format (preferred)
            policy:
              minimum_review_seconds:
                medium: 3
                high: 10
              fail_mode: deny
            risk:
              overrides:
                deploy_production: critical
            trust:
              influence: 0.3
              ceiling: 0.9

            # Legacy flat format (still supported)
            default_environment: production
            min_review_seconds: 2.0
            challenge_map:
              low: auto_approve
              medium: confirm

        Parameters
        ----------
        path:
            Filesystem path to the configuration file.

        Returns
        -------
        Attesta
            A fully configured instance.
        """
        filepath = Path(path)
        if not filepath.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        raw = filepath.read_text(encoding="utf-8")

        # Support both YAML and JSON.  We try YAML first (it is a superset
        # of JSON), falling back to stdlib json if PyYAML is unavailable.
        data: dict[str, Any]
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(raw) or {}
        except ImportError:
            # PyYAML not installed -- only proceed with json if the file
            # looks like JSON (not YAML).  Otherwise give a clear error.
            if filepath.suffix.lower() in (".yaml", ".yml"):
                raise ImportError(
                    f"Cannot load YAML config '{filepath}': PyYAML is not "
                    f"installed.  Install it with:  pip install attesta[yaml]"
                ) from None
            import json

            data = json.loads(raw)

        if not isinstance(data, dict):
            raise TypeError(
                f"Expected a mapping at the top level of {filepath}, "
                f"got {type(data).__name__}"
            )

        # Detect whether this is a rich config (structured sections or
        # top-level advanced keys) or a simple legacy flat dict.
        _rich_keys = {"policy", "risk", "trust", "domain", "domain_strict", "audit"}
        if _rich_keys & data.keys():
            return cls._from_rich_config(filepath, data)

        # Legacy flat format -- fall back to original behaviour.
        return cls(policy=data)

    @classmethod
    def _from_rich_config(cls, filepath: Path, data: dict[str, Any]) -> Attesta:
        """Build an Attesta instance from a rich config dict using
        :func:`~attesta.config.loader.load_config`.
        """
        from attesta.config.loader import load_config

        policy_obj = load_config(filepath)

        # Challenge map from the Policy object.
        challenge_map = policy_obj.to_challenge_map()

        # Use MEDIUM-level minimum review time as the default.
        min_review_seconds = policy_obj.min_review_time(RiskLevel.MEDIUM)

        # Build a domain-aware risk scorer if a domain is configured.
        risk_scorer_inst: RiskScorer | None = None
        try:
            risk_scorer_inst = policy_obj.build_risk_scorer()
        except KeyError as exc:
            raise ValueError(
                "Configured domain profile was not found: "
                f"{policy_obj.domain!r}. Register the profile with "
                "attesta.domains.presets.register_preset(), or set "
                "domain_strict: false to continue without domain scoring."
            ) from exc
        except Exception:
            logger.warning(
                "Failed to initialise domain risk scorer from config; "
                "continuing with default scorer."
            )

        # Build a TrustEngine if trust settings are present in the YAML.
        trust_engine: Any | None = None
        if data.get("trust"):
            try:
                from attesta.core.trust import TrustEngine

                trust_engine = TrustEngine(**policy_obj.to_trust_engine_kwargs())
            except Exception:
                logger.warning(
                    "Failed to initialise TrustEngine from config; "
                    "continuing without trust."
                )

        # Build an AuditLogger if audit settings are present.
        audit_logger_inst: AuditLogger | None = None
        audit_data = data.get("audit")
        if audit_data and isinstance(audit_data, dict):
            try:
                from attesta.core.audit import AuditLogger as _AuditLogger

                audit_path = audit_data.get("path", ".attesta/audit.jsonl")
                audit_logger_inst = _AuditLogger(path=audit_path)
            except Exception:
                logger.warning(
                    "Failed to initialise AuditLogger from config; "
                    "continuing without persistent audit."
                )

        # Try to use a TerminalRenderer if `rich` is available.
        renderer_inst: Renderer | None = None
        try:
            from attesta.renderers.terminal import TerminalRenderer

            renderer_inst = TerminalRenderer()
        except (ImportError, Exception):
            # Fall back to default (auto-approve) renderer.
            pass

        # Preserve the raw dict for backward compat of .policy property.
        instance = cls(
            policy=data,
            risk_scorer=risk_scorer_inst,
            renderer=renderer_inst,
            audit_logger=audit_logger_inst,
            trust_engine=trust_engine,
            fail_mode=policy_obj.fail_mode,
            timeout_seconds=policy_obj.timeout_seconds,
        )
        # Override the challenge map and min_review_seconds derived from
        # the rich Policy object (they take precedence over the raw dict
        # parse done in __init__).
        instance._challenge_map = challenge_map
        instance._policy["min_review_seconds"] = min_review_seconds
        instance._policy["fail_mode"] = policy_obj.fail_mode
        instance._policy["timeout_seconds"] = policy_obj.timeout_seconds
        instance._policy_obj = policy_obj
        return instance

    def gate(
        self,
        fn: F | None = None,
        /,
        *,
        risk: RiskLevel | str | None = None,
        risk_hints: dict[str, Any] | None = None,
        risk_scorer: RiskScorer | None = None,
        renderer: Renderer | None = None,
        audit_logger: AuditLogger | None = None,
        challenge_map: dict[RiskLevel, ChallengeType] | None = None,
        min_review_seconds: float | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        environment: str | None = None,
        metadata: dict[str, Any] | None = None,
        allow_hint_override: bool | None = None,
        fail_mode: str | None = None,
        approval_timeout_seconds: float | None = None,
    ) -> F | Callable[[F], F]:
        """Decorator factory -- like the module-level :func:`gate`, but uses
        this instance's defaults for any parameters not explicitly provided.

        Supports the same three calling styles::

            @attesta.gate
            @attesta.gate()
            @attesta.gate(risk="high")
        """
        # Resolve defaults from the instance / policy.
        resolved_scorer = risk_scorer or self._risk_scorer
        resolved_renderer = renderer or self._renderer
        resolved_audit = audit_logger or self._audit_logger
        resolved_challenge_map = challenge_map or self._challenge_map
        resolved_env = environment or self._policy.get(
            "default_environment", "development"
        )
        resolved_min_review = (
            min_review_seconds
            if min_review_seconds is not None
            else self._policy.get("min_review_seconds", 0.0)
        )
        resolved_fail_mode = str(fail_mode or self._fail_mode)
        resolved_timeout_seconds = (
            approval_timeout_seconds
            if approval_timeout_seconds is not None
            else self._timeout_seconds
        )

        def decorator(func: F) -> F:
            from attesta.core.gate import gate as _raw_gate

            return _raw_gate(
                func,
                risk=risk,
                risk_hints=risk_hints,
                risk_scorer=resolved_scorer,
                renderer=resolved_renderer,
                audit_logger=resolved_audit,
                challenge_map=resolved_challenge_map,
                min_review_seconds=resolved_min_review,
                agent_id=agent_id,
                session_id=session_id,
                environment=resolved_env,
                metadata=metadata,
                trust_engine=self._trust_engine,
                allow_hint_override=(
                    self._allow_hint_override
                    if allow_hint_override is None
                    else allow_hint_override
                ),
                fail_mode=resolved_fail_mode,
                approval_timeout_seconds=resolved_timeout_seconds,
            )

        if fn is not None:
            return decorator(fn)
        return decorator  # type: ignore[return-value]

    @property
    def policy(self) -> dict[str, Any]:
        """Return a copy of the active policy dict."""
        return dict(self._policy)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _parse_challenge_map(
        raw: dict[str, str] | None,
    ) -> dict[RiskLevel, ChallengeType] | None:
        """Convert string-keyed YAML challenge map to typed enums."""
        if raw is None:
            return None
        result: dict[RiskLevel, ChallengeType] = {}
        for level_str, challenge_str in raw.items():
            try:
                level = RiskLevel(level_str)
            except ValueError:
                logger.warning("Unknown risk level in challenge_map: %s", level_str)
                continue
            try:
                challenge = ChallengeType(challenge_str)
            except ValueError:
                logger.warning(
                    "Unknown challenge type in challenge_map: %s", challenge_str
                )
                continue
            result[level] = challenge
        return result or None
