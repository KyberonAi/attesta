"""Domain knowledge profiles for attesta.

This package provides industry-specific risk profiles that tune the
attesta's scoring, challenge selection, and escalation behaviour to
match the regulatory and operational requirements of a given domain.

The framework provides the base types and registry; you supply the
domain-specific content (risk patterns, sensitive terms, compliance
references, etc.) by creating :class:`DomainProfile` instances.

Quick start::

    from attesta.domains import (
        DomainProfile,
        DomainRegistry,
        DomainRiskScorer,
        EscalationRule,
        RiskPattern,
        registry,
    )

    # Create a profile
    my_domain = DomainProfile(
        name="my-domain",
        display_name="My Domain",
        description="Custom risk profile for my industry.",
        sensitive_terms={"confidential": 0.7, "secret": 0.9},
    )

    # Register it
    registry.register(my_domain)

    # Create a domain-aware scorer
    scorer = DomainRiskScorer(my_domain)
"""

from attesta.domains.profile import (
    DomainChallengeTemplate,
    DomainProfile,
    DomainRegistry,
    EscalationRule,
    RiskPattern,
    registry,
)
from attesta.domains.scorer import DomainRiskScorer

__all__ = [
    # profile.py
    "DomainChallengeTemplate",
    "DomainProfile",
    "DomainRegistry",
    "EscalationRule",
    "RiskPattern",
    "registry",
    # scorer.py
    "DomainRiskScorer",
]
