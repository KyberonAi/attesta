"""Core type definitions for attesta-ai.

This module defines the foundational data structures, enums, and protocols
that all other modules depend on. It is intentionally dependency-free
(no imports from other attesta modules) so it can be imported anywhere
without circular-import issues.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(Enum):
    """Discrete risk classification derived from a continuous 0-1 score."""

    LOW = "low"           # 0.0 - 0.3
    MEDIUM = "medium"     # 0.3 - 0.6
    HIGH = "high"         # 0.6 - 0.8
    CRITICAL = "critical" # 0.8 - 1.0

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        """Map a continuous risk score in [0, 1] to a discrete level."""
        if score < 0.0 or score > 1.0:
            raise ValueError(f"Risk score must be in [0, 1], got {score}")
        if score < 0.3:
            return cls.LOW
        if score < 0.6:
            return cls.MEDIUM
        if score < 0.8:
            return cls.HIGH
        return cls.CRITICAL


class Verdict(Enum):
    """The outcome of a attesta review."""

    APPROVED = "approved"
    DENIED = "denied"
    MODIFIED = "modified"
    TIMED_OUT = "timed_out"
    ESCALATED = "escalated"


class ChallengeType(Enum):
    """The kind of verification challenge presented to the operator."""

    AUTO_APPROVE = "auto_approve"
    CONFIRM = "confirm"
    QUIZ = "quiz"
    TEACH_BACK = "teach_back"
    MULTI_PARTY = "multi_party"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ActionContext:
    """All information about a single function invocation under review.

    The gate decorator builds this automatically from the wrapped call,
    but callers may also construct one manually for programmatic use.
    """

    function_name: str
    args: tuple = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    function_doc: str | None = None
    hints: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    session_id: str | None = None
    environment: str = "development"
    timestamp: datetime = field(default_factory=datetime.now)
    source_code: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def description(self) -> str:
        """Human-readable one-liner describing the call."""
        parts: list[str] = [repr(a) for a in self.args]
        parts.extend(f"{k}={v!r}" for k, v in self.kwargs.items())
        return f"{self.function_name}({', '.join(parts)})"


@dataclass
class RiskFactor:
    """A single contributing factor to an overall risk score."""

    name: str
    contribution: float
    description: str
    evidence: str | None = None


@dataclass
class RiskAssessment:
    """The result of evaluating the risk of an action."""

    score: float
    level: RiskLevel
    factors: list[RiskFactor] = field(default_factory=list)
    scorer_name: str = "default"

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Risk score must be in [0, 1], got {self.score}")


@dataclass
class ChallengeResult:
    """Outcome of a verification challenge."""

    passed: bool
    challenge_type: ChallengeType
    responder: str = "default"
    response_time_seconds: float = 0.0
    questions_asked: int = 0
    questions_correct: int = 0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalResult:
    """Full audit-ready record of a attesta decision."""

    verdict: Verdict
    risk_assessment: RiskAssessment
    challenge_result: ChallengeResult | None = None
    approvers: list[str] = field(default_factory=list)
    review_time_seconds: float = 0.0
    audit_entry_id: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    modification: str | None = None  # populated when verdict is MODIFIED
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocols (structural sub-typing)
# ---------------------------------------------------------------------------

@runtime_checkable
class RiskScorer(Protocol):
    """Anything that can assign a 0-1 risk score to an action."""

    def score(self, ctx: ActionContext) -> float: ...

    @property
    def name(self) -> str: ...


@runtime_checkable
class ChallengeProtocol(Protocol):
    """Anything that can present a verification challenge."""

    async def present(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> ChallengeResult: ...

    @property
    def challenge_type(self) -> ChallengeType: ...


@runtime_checkable
class Renderer(Protocol):
    """UI / UX layer for presenting gates to the operator."""

    async def render_approval(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> Verdict: ...

    async def render_challenge(
        self,
        ctx: ActionContext,
        risk: RiskAssessment,
        challenge_type: ChallengeType,
    ) -> ChallengeResult: ...

    async def render_info(self, message: str) -> None: ...

    async def render_auto_approved(
        self, ctx: ActionContext, risk: RiskAssessment
    ) -> None: ...


@runtime_checkable
class TeachBackValidator(Protocol):
    """Anything that can validate a teach-back explanation."""

    async def validate(
        self, explanation: str, context: ActionContext
    ) -> tuple[bool, str]:
        """Validate *explanation* and return ``(passed, notes)``."""
        ...


@runtime_checkable
class AuditLogger(Protocol):
    """Anything that can persist an approval record for auditing."""

    async def log(self, ctx: ActionContext, result: ApprovalResult) -> str:
        """Persist *result* and return a unique audit-entry ID."""
        ...
