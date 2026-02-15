"""Bayesian-inspired adaptive trust engine.

Trust is computed per-agent and optionally per-domain using a model that
combines three signals:

1. **Weighted success rate** -- recent actions matter more than old ones
   (exponential decay weighting).
2. **Recency factor** -- trust decays if an agent has been inactive.
3. **Incident penalty** -- each security incident multiplicatively reduces
   trust.

Trust scores influence the *effective risk* of an action: a highly trusted
agent may see slightly reduced risk scores, but trust never fully bypasses
CRITICAL actions and is capped below 1.0 as a safety ceiling.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class TrustRecord:
    """A single trust-relevant event."""

    timestamp: datetime
    action_name: str
    domain: str
    outcome: str  # "success", "denied", "incident"
    risk_score: float


@dataclass
class TrustProfile:
    """Trust profile for an agent."""

    agent_id: str
    overall_score: float = 0.3  # start cautious
    domain_scores: dict[str, float] = field(default_factory=dict)
    history: list[TrustRecord] = field(default_factory=list)
    incidents: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    last_action_at: datetime | None = None


class TrustEngine:
    """Adaptive trust engine using Bayesian-inspired model.

    Trust = weighted_success_rate * recency_factor * incident_penalty

    - Trust is per-agent, per-domain
    - Trust decays over time (inactivity)
    - Trust never fully bypasses CRITICAL actions
    - Trust can be instantly revoked
    """

    def __init__(
        self,
        initial_score: float = 0.3,
        ceiling: float = 0.9,
        decay_rate: float = 0.01,  # per day
        incident_penalty: float = 0.7,  # multiply by this per incident
        influence: float = 0.3,  # max risk reduction from trust
        storage_path: Path | None = None,
    ):
        self.initial_score = initial_score
        self.ceiling = ceiling
        self.decay_rate = decay_rate
        self.incident_penalty = incident_penalty
        self.influence = influence
        self.storage_path = storage_path
        self._profiles: dict[str, TrustProfile] = {}

        if storage_path and storage_path.exists():
            self._load()

    def get_profile(self, agent_id: str) -> TrustProfile:
        if agent_id not in self._profiles:
            self._profiles[agent_id] = TrustProfile(
                agent_id=agent_id,
                overall_score=self.initial_score,
            )
        return self._profiles[agent_id]

    def compute_trust(self, agent_id: str, domain: str | None = None) -> float:
        """Compute current trust score for an agent, optionally for a specific domain."""
        profile = self.get_profile(agent_id)

        # Filter history by domain if specified
        history = [r for r in profile.history if domain is None or r.domain == domain]

        if not history:
            return self.initial_score

        now = datetime.now()

        # Exponentially weighted success rate
        total_weight = 0.0
        success_weight = 0.0
        for record in history:
            days_ago = (now - record.timestamp).total_seconds() / 86400
            weight = math.exp(-0.1 * days_ago)  # recent events matter more
            total_weight += weight
            if record.outcome == "success":
                success_weight += weight

        weighted_rate = success_weight / total_weight if total_weight > 0 else 0.5

        # Recency factor: trust decays if agent hasn't acted recently
        if profile.last_action_at:
            days_since = (now - profile.last_action_at).total_seconds() / 86400
            recency_factor = math.exp(-self.decay_rate * days_since)
        else:
            recency_factor = 1.0

        # Incident penalty
        penalty = self.incident_penalty ** profile.incidents

        raw_score = weighted_rate * recency_factor * penalty
        return min(raw_score, self.ceiling)

    def effective_risk(
        self, raw_risk: float, agent_id: str, domain: str | None = None
    ) -> float:
        """Adjust risk score based on trust. High trust reduces effective risk."""
        trust = self.compute_trust(agent_id, domain)
        trust_discount = (trust - 0.5) * self.influence
        adjusted = raw_risk * (1.0 - trust_discount)
        return max(0.0, min(1.0, adjusted))

    def record_success(
        self,
        agent_id: str,
        action_name: str,
        domain: str = "general",
        risk_score: float = 0.5,
    ):
        profile = self.get_profile(agent_id)
        record = TrustRecord(
            timestamp=datetime.now(),
            action_name=action_name,
            domain=domain,
            outcome="success",
            risk_score=risk_score,
        )
        profile.history.append(record)
        profile.last_action_at = datetime.now()
        profile.overall_score = self.compute_trust(agent_id)
        if domain:
            profile.domain_scores[domain] = self.compute_trust(agent_id, domain)
        self._save()

    def record_denial(
        self,
        agent_id: str,
        action_name: str,
        domain: str = "general",
        risk_score: float = 0.5,
    ):
        profile = self.get_profile(agent_id)
        record = TrustRecord(
            timestamp=datetime.now(),
            action_name=action_name,
            domain=domain,
            outcome="denied",
            risk_score=risk_score,
        )
        profile.history.append(record)
        profile.last_action_at = datetime.now()
        self._save()

    def record_incident(
        self,
        agent_id: str,
        action_name: str = "",
        domain: str = "general",
        severity: str = "medium",
        description: str = "",
    ):
        profile = self.get_profile(agent_id)
        profile.incidents += 1
        record = TrustRecord(
            timestamp=datetime.now(),
            action_name=action_name,
            domain=domain,
            outcome="incident",
            risk_score=1.0,
        )
        profile.history.append(record)
        profile.overall_score = self.compute_trust(agent_id)
        self._save()

    def revoke(self, agent_id: str):
        """Instantly revoke all trust for an agent."""
        profile = self.get_profile(agent_id)
        profile.overall_score = 0.0
        profile.domain_scores = {}
        profile.incidents += 3  # heavy penalty
        self._save()

    def _save(self):
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for agent_id, profile in self._profiles.items():
            data[agent_id] = {
                "overall_score": profile.overall_score,
                "domain_scores": profile.domain_scores,
                "incidents": profile.incidents,
                "created_at": profile.created_at.isoformat(),
                "last_action_at": (
                    profile.last_action_at.isoformat()
                    if profile.last_action_at
                    else None
                ),
                "history_count": len(profile.history),
            }
        self.storage_path.write_text(json.dumps(data, indent=2))

    def _load(self):
        if not self.storage_path or not self.storage_path.exists():
            return
        data = json.loads(self.storage_path.read_text())
        for agent_id, info in data.items():
            self._profiles[agent_id] = TrustProfile(
                agent_id=agent_id,
                overall_score=info.get("overall_score", self.initial_score),
                domain_scores=info.get("domain_scores", {}),
                incidents=info.get("incidents", 0),
                created_at=(
                    datetime.fromisoformat(info["created_at"])
                    if "created_at" in info
                    else datetime.now()
                ),
                last_action_at=(
                    datetime.fromisoformat(info["last_action_at"])
                    if info.get("last_action_at")
                    else None
                ),
            )
