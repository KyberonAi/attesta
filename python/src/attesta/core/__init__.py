"""attesta.core -- foundational types, the Attesta class, and the @gate decorator."""

from attesta.core.gate import Attesta, AttestaDenied, gate
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

__all__ = [
    # Attesta
    "Attesta",
    "AttestaDenied",
    "gate",
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
]
