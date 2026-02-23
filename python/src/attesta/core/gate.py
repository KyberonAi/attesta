"""Attesta orchestrator and @gate decorator.

This module provides the ``@gate`` decorator -- the primary user-facing API
for protecting function calls -- and the ``Attesta`` class that orchestrates the
full risk-scoring -> challenge-selection -> verification -> audit pipeline.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import inspect
import logging
import textwrap
import threading
import time
import uuid
from collections.abc import Callable, Coroutine
from typing import Any, Literal, TypeVar, overload

from attesta.core.types import (
    ActionContext,
    ApprovalResult,
    AuditLogger,
    ChallengeResult,
    ChallengeType,
    Renderer,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    RiskScorer,
    Verdict,
)

__all__ = ["Attesta", "AttestaDenied", "gate"]

logger = logging.getLogger("attesta")

# Internal ActionContext.metadata key used by first-party integrations for
# trusted, static risk overrides (for example MCP tool maps). This bypasses
# hint-based overrides without reopening user-controlled hint injection.
TRUSTED_RISK_OVERRIDE_METADATA_KEY = "_attesta_trusted_risk_override"

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class AttestaDenied(Exception):  # noqa: N818
    """Raised when a gated function call is denied by the reviewer."""

    def __init__(
        self,
        message: str = "Action denied by attesta",
        *,
        result: ApprovalResult | None = None,
    ) -> None:
        super().__init__(message)
        self.result = result


# ---------------------------------------------------------------------------
# Default implementations (used when no external components are supplied)
# ---------------------------------------------------------------------------


def _get_default_risk_scorer() -> RiskScorer:
    """Return the full 5-factor :class:`DefaultRiskScorer` from ``attesta.core.risk``.

    This scorer analyses function names, arguments, docstrings, caller hints,
    and call novelty to produce a weighted risk score.  It is the scorer
    described in the documentation and README.
    """
    from attesta.core.risk import DefaultRiskScorer

    return DefaultRiskScorer()


class _DefaultRenderer:
    """Auto-approves everything -- suitable for CI / non-interactive use."""

    async def render_approval(self, ctx: ActionContext, risk: RiskAssessment) -> Verdict:
        return Verdict.APPROVED

    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult:
        return ChallengeResult(
            passed=True,
            challenge_type=challenge_type,
            responder="auto",
        )

    async def render_info(self, message: str) -> None:
        logger.info(message)

    async def render_auto_approved(self, ctx: ActionContext, risk: RiskAssessment) -> None:
        logger.debug("Auto-approved %s (risk=%.2f)", ctx.function_name, risk.score)


def _detect_renderer() -> Renderer:
    """Return the best available renderer for the current environment.

    If ``rich`` is installed and stdin is a TTY (interactive session),
    returns a :class:`~attesta.renderers.terminal.TerminalRenderer`.
    Otherwise falls back to the silent :class:`_DefaultRenderer` (auto-
    approve, suitable for CI / headless).
    """
    import sys

    if sys.stdin.isatty():
        try:
            from attesta.renderers.terminal import TerminalRenderer

            return TerminalRenderer()
        except (ImportError, Exception):
            pass
    return _DefaultRenderer()


class _DefaultAuditLogger:
    """Writes audit records to the Python logger (no persistence)."""

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        entry_id = uuid.uuid4().hex[:12]
        logger.info(
            "[audit:%s] %s -> %s (risk=%.2f)",
            entry_id,
            ctx.description,
            result.verdict.value,
            result.risk_assessment.score,
        )
        return entry_id


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------

# Default mapping from risk level to challenge type.
_DEFAULT_CHALLENGE_MAP: dict[RiskLevel, ChallengeType] = {
    RiskLevel.LOW: ChallengeType.AUTO_APPROVE,
    RiskLevel.MEDIUM: ChallengeType.CONFIRM,
    RiskLevel.HIGH: ChallengeType.QUIZ,
    RiskLevel.CRITICAL: ChallengeType.MULTI_PARTY,
}


def _select_challenge(
    risk: RiskAssessment,
    challenge_map: dict[RiskLevel, ChallengeType] | None = None,
) -> ChallengeType:
    """Pick the appropriate challenge for a given risk level."""
    mapping = challenge_map or _DEFAULT_CHALLENGE_MAP
    return mapping.get(risk.level, ChallengeType.CONFIRM)


# ---------------------------------------------------------------------------
# Attesta class
# ---------------------------------------------------------------------------


class Attesta:
    """Orchestrates the full approval pipeline for a single gated action.

    Typical lifecycle::

        attesta = Attesta(risk_scorer=scorer, renderer=renderer, audit_logger=audit)
        result = await attesta.evaluate(ctx)
        # result.verdict tells you what happened

    Parameters
    ----------
    risk_scorer:
        Assigns a 0-1 risk score to an action.
    renderer:
        Presents challenges / approval prompts to the operator.
    audit_logger:
        Persists the approval record.
    challenge_map:
        Override the default risk-level -> challenge-type mapping.
    min_review_seconds:
        Minimum wall-clock time the review must take.  Useful to prevent
        rubber-stamping of high-risk actions.
    risk_override:
        If set, bypass the scorer and use this risk level directly.
    risk_hints:
        Extra hints merged into the ``ActionContext.hints`` dict.
    trust_engine:
        Optional trust engine for adaptive risk adjustment.  When
        provided and the action has an ``agent_id``, the engine adjusts
        the risk score after initial scoring and records the outcome
        (success/denial) after the verdict.  CRITICAL-level actions are
        never downgraded by trust (safety invariant).
    """

    _VALID_MODES: frozenset[str] = frozenset({"enforce", "shadow", "audit_only"})
    _VALID_FAIL_MODES: frozenset[str] = frozenset({"deny", "allow", "escalate"})

    def __init__(
        self,
        *,
        risk_scorer: RiskScorer | None = None,
        renderer: Renderer | None = None,
        audit_logger: AuditLogger | None = None,
        challenge_map: dict[RiskLevel, ChallengeType] | None = None,
        min_review_seconds: float = 0.0,
        risk_override: RiskLevel | str | None = None,
        risk_hints: dict[str, Any] | None = None,
        trust_engine: Any | None = None,
        event_bus: Any | None = None,
        allow_hint_override: bool = False,
        mode: str = "enforce",
        fail_mode: Literal["deny", "allow", "escalate"] = "deny",
        approval_timeout_seconds: float = 600.0,
    ) -> None:
        if mode not in self._VALID_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Must be one of {sorted(self._VALID_MODES)}")
        if fail_mode not in self._VALID_FAIL_MODES:
            raise ValueError(f"Invalid fail_mode '{fail_mode}'. Must be one of {sorted(self._VALID_FAIL_MODES)}")
        if approval_timeout_seconds <= 0:
            raise ValueError(f"approval_timeout_seconds must be > 0, got {approval_timeout_seconds}")

        self._scorer: RiskScorer = risk_scorer or _get_default_risk_scorer()
        self._renderer: Renderer = renderer or _detect_renderer()
        self._audit: AuditLogger = audit_logger or _DefaultAuditLogger()
        self._challenge_map = challenge_map
        self._min_review_seconds = min_review_seconds
        self._risk_hints = risk_hints or {}
        self._trust_engine = trust_engine
        self._event_bus = event_bus
        self._allow_hint_override = allow_hint_override
        self._mode = mode
        self._fail_mode = fail_mode
        self._approval_timeout = approval_timeout_seconds

        # Normalise risk_override to a RiskLevel or None.
        if isinstance(risk_override, str):
            self._risk_override: RiskLevel | None = RiskLevel(risk_override)
        else:
            self._risk_override = risk_override

    # -- public API --------------------------------------------------------

    async def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event if an event bus is configured. No-op otherwise."""
        if self._event_bus is None:
            return
        from attesta.events import Event, EventType

        try:
            event = Event(type=EventType(event_type), data=data)
            await self._event_bus.async_emit(event)
        except Exception:
            logger.exception("Failed to emit event %s", event_type)

    async def evaluate(self, ctx: ActionContext) -> ApprovalResult:
        """Run the full approval pipeline and return the result."""
        review_start = time.monotonic()

        # 1. Merge extra hints.
        if self._risk_hints:
            ctx.hints = {**ctx.hints, **self._risk_hints}

        # 2. Risk scoring.
        risk = self._assess_risk(ctx)

        # 2a. Environment risk multiplier (skip if risk was manually overridden).
        if self._risk_override is None:
            from attesta.environment import RISK_MULTIPLIERS

            env_multiplier = RISK_MULTIPLIERS.get(ctx.environment, 1.0)
            if env_multiplier != 1.0:
                adjusted_score = min(1.0, max(0.0, risk.score * env_multiplier))
                adjusted_level = RiskLevel.from_score(adjusted_score)
                risk = RiskAssessment(
                    score=adjusted_score,
                    level=adjusted_level,
                    factors=risk.factors
                    + [
                        RiskFactor(
                            name="environment_multiplier",
                            contribution=adjusted_score - risk.score,
                            description=(
                                f"Environment '{ctx.environment}' multiplier "
                                f"{env_multiplier}x adjusted risk from "
                                f"{risk.score:.2f} to {adjusted_score:.2f}"
                            ),
                        )
                    ],
                    scorer_name=risk.scorer_name,
                )

        await self._emit(
            "risk_scored",
            {
                "action_name": ctx.function_name,
                "risk_score": risk.score,
                "risk_level": risk.level.value,
            },
        )

        # 2b. Trust-based risk adjustment.
        #     If a trust engine is available and the action has an agent_id,
        #     adjust the risk score.  CRITICAL risk is NEVER downgraded
        #     (safety invariant).
        original_level = risk.level
        if self._trust_engine is not None and ctx.agent_id:
            domain = ctx.hints.get("domain") or ctx.environment or "general"
            adjusted_score = self._trust_engine.effective_risk(risk.score, ctx.agent_id, domain)
            adjusted_score = max(0.0, min(1.0, adjusted_score))
            adjusted_level = RiskLevel.from_score(adjusted_score)

            # Safety invariant: CRITICAL actions must NEVER be downgraded.
            if original_level != RiskLevel.CRITICAL:
                risk = RiskAssessment(
                    score=adjusted_score,
                    level=adjusted_level,
                    factors=risk.factors
                    + [
                        RiskFactor(
                            name="trust_adjustment",
                            contribution=adjusted_score - risk.score,
                            description=(f"Trust engine adjusted risk from {risk.score:.2f} to {adjusted_score:.2f}"),
                        )
                    ],
                    scorer_name=risk.scorer_name,
                )

        # 3. Select challenge.
        challenge_type = _select_challenge(risk, self._challenge_map)

        # 3a. Mode handling -- audit_only and shadow modes alter the
        #     challenge / verdict flow while preserving the audit trail.
        mode_metadata: dict[str, Any] = {
            "mode": self._mode,
            "fail_mode": self._fail_mode,
            "approval_timeout_seconds": self._approval_timeout,
        }

        if self._mode == "audit_only":
            # Skip the challenge entirely; auto-approve and record.
            verdict = Verdict.APPROVED
            challenge_result: ChallengeResult | None = None
            mode_metadata["skipped_challenge"] = challenge_type.value
            logger.info(
                "[audit_only] Auto-approved %s (risk=%.2f, level=%s, would_challenge=%s)",
                ctx.function_name,
                risk.score,
                risk.level.value,
                challenge_type.value,
            )

        elif self._mode == "shadow":
            # Run the full challenge but always approve, logging what
            # would have happened under enforce mode.
            challenge_result = None
            if challenge_type == ChallengeType.AUTO_APPROVE:
                enforce_verdict = Verdict.APPROVED
                await self._renderer.render_auto_approved(ctx, risk)
            else:
                await self._emit(
                    "challenge_issued",
                    {
                        "action_name": ctx.function_name,
                        "challenge_type": challenge_type.value,
                        "risk_level": risk.level.value,
                    },
                )
                challenge_result = await self._renderer.render_challenge(ctx, risk, challenge_type)
                enforce_verdict = Verdict.APPROVED if challenge_result.passed else Verdict.DENIED
                await self._emit(
                    "challenge_completed",
                    {
                        "action_name": ctx.function_name,
                        "challenge_type": challenge_type.value,
                        "passed": challenge_result.passed,
                    },
                )

            # Always approve in shadow mode, but log the enforce outcome.
            verdict = Verdict.APPROVED
            mode_metadata["enforce_verdict"] = enforce_verdict.value
            mode_metadata["challenge_type"] = challenge_type.value
            if challenge_result is not None:
                mode_metadata["challenge_passed"] = challenge_result.passed
            logger.info(
                "[shadow] %s -> approved (enforce would have: %s, risk=%.2f, level=%s)",
                ctx.function_name,
                enforce_verdict.value,
                risk.score,
                risk.level.value,
            )

        else:
            # 4. Present challenge / collect verdict (enforce mode).
            challenge_result = None
            if challenge_type == ChallengeType.AUTO_APPROVE:
                verdict = Verdict.APPROVED
                await self._renderer.render_auto_approved(ctx, risk)
            else:
                await self._emit(
                    "challenge_issued",
                    {
                        "action_name": ctx.function_name,
                        "challenge_type": challenge_type.value,
                        "risk_level": risk.level.value,
                    },
                )
                try:
                    challenge_result = await asyncio.wait_for(
                        self._renderer.render_challenge(ctx, risk, challenge_type),
                        timeout=self._approval_timeout,
                    )
                except TimeoutError:
                    logger.warning(
                        "Approval timed out after %.0fs for %s",
                        self._approval_timeout,
                        ctx.function_name,
                    )
                    timeout_reason = f"Approval timed out after {self._approval_timeout:.0f}s"
                    if self._fail_mode == "allow":
                        verdict = Verdict.APPROVED
                    elif self._fail_mode == "escalate":
                        verdict = Verdict.ESCALATED
                    else:
                        verdict = Verdict.TIMED_OUT
                    challenge_result = ChallengeResult(
                        passed=False,
                        challenge_type=challenge_type,
                        details={
                            "reason": timeout_reason,
                            "fail_mode": self._fail_mode,
                            "timeout_seconds": self._approval_timeout,
                        },
                    )
                    mode_metadata["timed_out"] = True
                    mode_metadata["timeout_reason"] = timeout_reason
                else:
                    verdict = Verdict.APPROVED if challenge_result.passed else Verdict.DENIED
                await self._emit(
                    "challenge_completed",
                    {
                        "action_name": ctx.function_name,
                        "challenge_type": challenge_type.value,
                        "passed": challenge_result.passed if challenge_result else False,
                    },
                )

        # 5. Enforce minimum review time.
        elapsed = time.monotonic() - review_start
        remaining = self._min_review_seconds - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)

        review_time = time.monotonic() - review_start

        # 6. Build result.
        result = ApprovalResult(
            verdict=verdict,
            risk_assessment=risk,
            challenge_result=challenge_result,
            review_time_seconds=round(review_time, 3),
            metadata=mode_metadata,
        )

        # 6b. Emit verdict event.
        if verdict == Verdict.APPROVED:
            verdict_event = "approved"
        elif verdict == Verdict.ESCALATED:
            verdict_event = "escalated"
        else:
            verdict_event = "denied"
        await self._emit(
            verdict_event,
            {
                "action_name": ctx.function_name,
                "risk_score": risk.score,
                "risk_level": risk.level.value,
                "verdict": verdict.value,
            },
        )

        # 7. Audit.
        try:
            result.audit_entry_id = await self._audit.log(ctx, result)
        except Exception:
            logger.exception("Audit logging failed for %s", ctx.description)

        if result.audit_entry_id:
            await self._emit(
                "audit_logged",
                {
                    "action_name": ctx.function_name,
                    "audit_entry_id": result.audit_entry_id,
                    "verdict": verdict.value,
                },
            )

        # 8. Update trust engine with the outcome.
        if self._trust_engine is not None and ctx.agent_id:
            domain = ctx.hints.get("domain") or ctx.environment or "general"
            try:
                if verdict == Verdict.APPROVED:
                    self._trust_engine.record_success(
                        agent_id=ctx.agent_id,
                        action_name=ctx.function_name,
                        domain=domain,
                        risk_score=risk.score,
                    )
                elif verdict in {
                    Verdict.DENIED,
                    Verdict.TIMED_OUT,
                    Verdict.ESCALATED,
                }:
                    self._trust_engine.record_denial(
                        agent_id=ctx.agent_id,
                        action_name=ctx.function_name,
                        domain=domain,
                        risk_score=risk.score,
                    )
            except Exception:
                logger.exception("Trust engine update failed for %s", ctx.function_name)

        return result

    # -- internals ---------------------------------------------------------

    def _assess_risk(self, ctx: ActionContext) -> RiskAssessment:
        """Score risk, respecting any override.

        Override priority:
        1. ``self._risk_override`` (constructor parameter, e.g. ``@gate(risk="high")``)
        2. ``ctx.metadata[TRUSTED_RISK_OVERRIDE_METADATA_KEY]`` (trusted integration path)
        3. ``ctx.hints["risk_override"]`` (runtime hint from integrations,
           only if ``allow_hint_override=True``)
        4. Fall through to the risk scorer.
        """
        override = self._risk_override

        # First-party integrations can set a trusted metadata override. This
        # path is for static server-side mappings (e.g. tool-name policies),
        # not model-controlled runtime input.
        if override is None:
            trusted_override = ctx.metadata.get(TRUSTED_RISK_OVERRIDE_METADATA_KEY)
            if trusted_override is not None:
                try:
                    if isinstance(trusted_override, RiskLevel):
                        override = trusted_override
                    elif isinstance(trusted_override, str):
                        override = RiskLevel(trusted_override)
                    else:
                        raise TypeError(f"Unsupported trusted override type: {type(trusted_override).__name__}")
                except (ValueError, TypeError):
                    logger.warning(
                        "Ignoring invalid trusted risk override for %s: %r",
                        ctx.function_name,
                        trusted_override,
                    )

        # Allow integrations (MCP, LangChain, etc.) to set a runtime
        # risk override via the ActionContext hints dict.
        if override is None and self._allow_hint_override:
            hint_override = ctx.hints.get("risk_override")
            if hint_override is not None:
                try:
                    if isinstance(hint_override, RiskLevel):
                        override = hint_override
                    elif isinstance(hint_override, str):
                        override = RiskLevel(hint_override)
                    else:
                        raise TypeError(f"Unsupported hint override type: {type(hint_override).__name__}")
                except (ValueError, TypeError):
                    logger.warning(
                        "Ignoring invalid hint risk_override for %s: %r",
                        ctx.function_name,
                        hint_override,
                    )
        elif override is None and ctx.hints.get("risk_override") is not None:
            logger.warning(
                "risk_override hint ignored (allow_hint_override=False). "
                "Set allow_hint_override=True to enable runtime overrides."
            )

        if override is not None:
            # Map level back to a representative score.
            score_map = {
                RiskLevel.LOW: 0.15,
                RiskLevel.MEDIUM: 0.45,
                RiskLevel.HIGH: 0.70,
                RiskLevel.CRITICAL: 0.90,
            }
            score = score_map[override]
            return RiskAssessment(
                score=score,
                level=override,
                factors=[
                    RiskFactor(
                        name="manual_override",
                        contribution=score,
                        description=f"Risk level manually set to {override.value}",
                    )
                ],
                scorer_name="override",
            )

        raw_score = self._scorer.score(ctx)
        score = max(0.0, min(1.0, raw_score))
        level = RiskLevel.from_score(score)
        return RiskAssessment(
            score=score,
            level=level,
            scorer_name=self._scorer.name,
        )


# ---------------------------------------------------------------------------
# @gate decorator
# ---------------------------------------------------------------------------


def _build_context(
    fn: Callable[..., Any],
    args: tuple,
    kwargs: dict[str, Any],
    *,
    risk_hints: dict[str, Any] | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    environment: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> ActionContext:
    """Construct an :class:`ActionContext` from a live function call."""
    source: str | None = None
    try:
        source = textwrap.dedent(inspect.getsource(fn))
    except (OSError, TypeError):
        pass

    # Auto-detect environment if not explicitly provided.
    if environment is None:
        from attesta.environment import detect_environment

        environment = detect_environment().value

    return ActionContext(
        function_name=getattr(fn, "__qualname__", fn.__name__),
        args=args,
        kwargs=kwargs,
        function_doc=inspect.getdoc(fn),
        hints=dict(risk_hints or {}),
        agent_id=agent_id,
        session_id=session_id,
        environment=environment,
        source_code=source,
        metadata=dict(metadata or {}),
    )


def _ensure_loop() -> asyncio.AbstractEventLoop:
    """Return the running event loop, or create a new one if necessary."""
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.new_event_loop()


TResult = TypeVar("TResult")


def _run_coroutine_in_worker_thread(
    coro_factory: Callable[[], Coroutine[Any, Any, TResult]],
    *,
    timeout: float | None = None,
) -> TResult:
    """Run a coroutine on a dedicated thread with its own event loop.

    This avoids deadlocks when a synchronous ``@gate`` wrapper is invoked
    from inside an already-running event loop (for example in notebooks).
    """
    result_future: concurrent.futures.Future[TResult] = concurrent.futures.Future()

    def _runner() -> None:
        try:
            result = asyncio.run(coro_factory())
        except Exception as exc:
            result_future.set_exception(exc)
        else:
            result_future.set_result(result)

    thread = threading.Thread(
        target=_runner,
        name="attesta-sync-bridge",
        daemon=True,
    )
    thread.start()
    return result_future.result(timeout=timeout)


# Overloads let type-checkers understand each calling convention.


@overload
def gate(fn: F, /) -> F: ...  # @gate without parens


@overload
def gate(
    *,
    risk: RiskLevel | str | None = ...,
    risk_hints: dict[str, Any] | None = ...,
    risk_scorer: RiskScorer | None = ...,
    renderer: Renderer | None = ...,
    audit_logger: AuditLogger | None = ...,
    challenge_map: dict[RiskLevel, ChallengeType] | None = ...,
    min_review_seconds: float = ...,
    agent_id: str | None = ...,
    session_id: str | None = ...,
    environment: str = ...,
    metadata: dict[str, Any] | None = ...,
    trust_engine: Any | None = ...,
    event_bus: Any | None = ...,
    sync_timeout: float = ...,
    allow_hint_override: bool = ...,
    mode: str = ...,
    fail_mode: Literal["deny", "allow", "escalate"] = ...,
    approval_timeout_seconds: float = ...,
) -> Callable[[F], F]: ...  # @gate() or @gate(risk="high")


def gate(
    fn: F | None = None,
    /,
    *,
    risk: RiskLevel | str | None = None,
    risk_hints: dict[str, Any] | None = None,
    risk_scorer: RiskScorer | None = None,
    renderer: Renderer | None = None,
    audit_logger: AuditLogger | None = None,
    challenge_map: dict[RiskLevel, ChallengeType] | None = None,
    min_review_seconds: float = 0.0,
    agent_id: str | None = None,
    session_id: str | None = None,
    environment: str | None = None,
    metadata: dict[str, Any] | None = None,
    trust_engine: Any | None = None,
    event_bus: Any | None = None,
    sync_timeout: float = 300.0,
    allow_hint_override: bool = False,
    mode: str = "enforce",
    fail_mode: Literal["deny", "allow", "escalate"] = "deny",
    approval_timeout_seconds: float = 600.0,
) -> F | Callable[[F], F]:
    """Decorator that wraps a function with attesta approval.

    Supports three calling styles::

        @gate                             # bare
        @gate()                           # empty parens
        @gate(risk="high", ...)           # with options

    The decorator works on both synchronous and asynchronous functions.

    Parameters
    ----------
    risk:
        Explicit risk level override (e.g. ``"high"`` or ``RiskLevel.HIGH``).
    risk_hints:
        Dict of hints forwarded to the risk scorer (e.g. ``{"pii": True}``).
    risk_scorer / renderer / audit_logger / challenge_map:
        Override the default components for this gate.
    min_review_seconds:
        Minimum wall-clock time the review must take.
    agent_id / session_id / environment / metadata:
        Extra context fields attached to every :class:`ActionContext`.
    trust_engine:
        Optional trust engine for adaptive risk adjustment.  If set, the
        gate will adjust risk scores based on agent trust and record
        outcomes after each evaluation.
    sync_timeout:
        Maximum seconds to wait when bridging async evaluation from a
        synchronous context inside an already-running event loop (e.g.
        Jupyter).  Defaults to 300.  Set to ``0`` to wait indefinitely.
    mode:
        Execution mode for the gate.  One of:

        * ``"enforce"`` (default) -- full challenge flow; denied actions
          raise :class:`AttestaDenied`.
        * ``"shadow"`` -- run the full challenge but always approve.
          The result metadata records what enforcement would have done.
        * ``"audit_only"`` -- skip challenges entirely, auto-approve
          every action, and log the risk assessment for analysis.
    approval_timeout_seconds:
        Maximum seconds to wait for a human response before timeout policy
        handling. Defaults to 600 (10 minutes).
    fail_mode:
        Timeout policy for non-auto-approved actions:

        * ``"deny"`` (default) -> return ``Verdict.TIMED_OUT`` and block.
        * ``"allow"`` -> return ``Verdict.APPROVED`` and continue.
        * ``"escalate"`` -> return ``Verdict.ESCALATED`` and block.
    """

    def decorator(func: F) -> F:
        gate_instance = Attesta(
            risk_scorer=risk_scorer,
            renderer=renderer,
            audit_logger=audit_logger,
            challenge_map=challenge_map,
            min_review_seconds=min_review_seconds,
            risk_override=risk,
            risk_hints=risk_hints,
            trust_engine=trust_engine,
            event_bus=event_bus,
            fail_mode=fail_mode,
            approval_timeout_seconds=approval_timeout_seconds,
            allow_hint_override=allow_hint_override,
            mode=mode,
        )

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = _build_context(
                    func,
                    args,
                    kwargs,
                    risk_hints=risk_hints,
                    agent_id=agent_id,
                    session_id=session_id,
                    environment=environment,
                    metadata=metadata,
                )
                result = await gate_instance.evaluate(ctx)

                if result.verdict == Verdict.DENIED:
                    raise AttestaDenied(f"Action denied: {ctx.description}", result=result)
                if result.verdict == Verdict.TIMED_OUT:
                    raise AttestaDenied(f"Action timed out: {ctx.description}", result=result)
                if result.verdict == Verdict.ESCALATED:
                    raise AttestaDenied(
                        f"Action escalated (not yet resolved): {ctx.description}",
                        result=result,
                    )
                return await func(*args, **kwargs)

            # Stash the Attesta instance on the wrapper for introspection.
            async_wrapper.__gate__ = gate_instance  # type: ignore[attr-defined]
            return async_wrapper  # type: ignore[return-value]

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = _build_context(
                    func,
                    args,
                    kwargs,
                    risk_hints=risk_hints,
                    agent_id=agent_id,
                    session_id=session_id,
                    environment=environment,
                    metadata=metadata,
                )

                # Run the async pipeline from a sync context.
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                if loop is not None and loop.is_running():
                    # Running sync code inside an active event loop thread.
                    # Evaluate on a dedicated worker thread to avoid deadlock.
                    result = _run_coroutine_in_worker_thread(
                        lambda: gate_instance.evaluate(ctx),
                        timeout=sync_timeout if sync_timeout > 0 else None,
                    )
                else:
                    result = asyncio.run(gate_instance.evaluate(ctx))

                if result.verdict == Verdict.DENIED:
                    raise AttestaDenied(f"Action denied: {ctx.description}", result=result)
                if result.verdict == Verdict.TIMED_OUT:
                    raise AttestaDenied(f"Action timed out: {ctx.description}", result=result)
                if result.verdict == Verdict.ESCALATED:
                    raise AttestaDenied(
                        f"Action escalated (not yet resolved): {ctx.description}",
                        result=result,
                    )
                return func(*args, **kwargs)

            sync_wrapper.__gate__ = gate_instance  # type: ignore[attr-defined]
            return sync_wrapper  # type: ignore[return-value]

    # Handle @gate (bare, no parentheses) vs @gate(...).
    if fn is not None:
        return decorator(fn)
    return decorator  # type: ignore[return-value]
