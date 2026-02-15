/**
 * Bayesian-inspired adaptive trust engine.
 *
 * Trust is computed per-agent and optionally per-domain using a model that
 * combines three signals:
 *
 * 1. Weighted success rate -- recent actions matter more than old ones
 *    (exponential decay weighting).
 * 2. Recency factor -- trust decays if an agent has been inactive.
 * 3. Incident penalty -- each security incident multiplicatively reduces trust.
 *
 * Trust scores influence the effective risk of an action: a highly trusted
 * agent may see slightly reduced risk scores, but trust never fully bypasses
 * CRITICAL actions and is capped below 1.0 as a safety ceiling.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// ---------------------------------------------------------------------------
// Data interfaces
// ---------------------------------------------------------------------------

/**
 * A single trust-relevant event.
 */
export interface TrustRecord {
  /** When the event occurred. */
  timestamp: Date;

  /** The name of the action taken. */
  actionName: string;

  /** The domain/category of the action. */
  domain: string;

  /** Outcome of the action: "success", "denied", or "incident". */
  outcome: "success" | "denied" | "incident";

  /** The risk score at the time of the action. */
  riskScore: number;
}

/**
 * Trust profile for an agent.
 */
export interface TrustProfile {
  /** The agent's unique identifier. */
  agentId: string;

  /** Current overall trust score. */
  overallScore: number;

  /** Per-domain trust scores. */
  domainScores: Record<string, number>;

  /** History of trust-relevant events. */
  history: TrustRecord[];

  /** Number of security incidents. */
  incidents: number;

  /** When this profile was created. */
  createdAt: Date;

  /** When the agent last performed an action. */
  lastActionAt?: Date;
}

// ---------------------------------------------------------------------------
// TrustEngine options
// ---------------------------------------------------------------------------

/**
 * Options for configuring the TrustEngine.
 */
export interface TrustEngineOptions {
  /** Starting trust score for new agents (default 0.3). */
  initialScore?: number;

  /** Maximum trust score (default 0.9). */
  ceiling?: number;

  /** Trust decay rate per day of inactivity (default 0.01). */
  decayRate?: number;

  /** Multiplicative penalty per incident (default 0.7). */
  incidentPenalty?: number;

  /** Maximum risk reduction from trust (default 0.3). */
  influence?: number;

  /** Filesystem path for persisting trust data (optional). */
  storagePath?: string;
}

// ---------------------------------------------------------------------------
// TrustEngine
// ---------------------------------------------------------------------------

/**
 * Adaptive trust engine using a Bayesian-inspired model.
 *
 * Trust = weighted_success_rate * recency_factor * incident_penalty
 *
 * - Trust is per-agent, per-domain
 * - Trust decays over time (inactivity)
 * - Trust never fully bypasses CRITICAL actions
 * - Trust can be instantly revoked
 */
export class TrustEngine {
  readonly initialScore: number;
  readonly ceiling: number;
  readonly decayRate: number;
  readonly incidentPenalty: number;
  readonly influence: number;
  readonly storagePath?: string;

  private _profiles = new Map<string, TrustProfile>();

  constructor(options: TrustEngineOptions = {}) {
    this.initialScore = options.initialScore ?? 0.3;
    this.ceiling = options.ceiling ?? 0.9;
    this.decayRate = options.decayRate ?? 0.01;
    this.incidentPenalty = options.incidentPenalty ?? 0.7;
    this.influence = options.influence ?? 0.3;
    this.storagePath = options.storagePath;

    if (this.storagePath && existsSync(this.storagePath)) {
      this._load();
    }
  }

  /**
   * Get or create a trust profile for the given agent.
   */
  getProfile(agentId: string): TrustProfile {
    let profile = this._profiles.get(agentId);
    if (!profile) {
      profile = {
        agentId,
        overallScore: this.initialScore,
        domainScores: {},
        history: [],
        incidents: 0,
        createdAt: new Date(),
        lastActionAt: undefined,
      };
      this._profiles.set(agentId, profile);
    }
    return profile;
  }

  /**
   * Compute current trust score for an agent, optionally for a specific domain.
   */
  computeTrust(agentId: string, domain?: string): number {
    const profile = this.getProfile(agentId);

    // Filter history by domain if specified
    const history =
      domain != null
        ? profile.history.filter((r) => r.domain === domain)
        : profile.history;

    if (history.length === 0) {
      return this.initialScore;
    }

    const now = Date.now();

    // Exponentially weighted success rate
    let totalWeight = 0;
    let successWeight = 0;
    for (const record of history) {
      const daysAgo =
        (now - record.timestamp.getTime()) / (86400 * 1000);
      const weight = Math.exp(-0.1 * daysAgo);
      totalWeight += weight;
      if (record.outcome === "success") {
        successWeight += weight;
      }
    }

    const weightedRate =
      totalWeight > 0 ? successWeight / totalWeight : 0.5;

    // Recency factor: trust decays if agent has not acted recently
    let recencyFactor = 1.0;
    if (profile.lastActionAt) {
      const daysSince =
        (now - profile.lastActionAt.getTime()) / (86400 * 1000);
      recencyFactor = Math.exp(-this.decayRate * daysSince);
    }

    // Incident penalty
    const penalty = Math.pow(this.incidentPenalty, profile.incidents);

    const rawScore = weightedRate * recencyFactor * penalty;
    return Math.min(rawScore, this.ceiling);
  }

  /**
   * Adjust risk score based on trust. High trust reduces effective risk.
   */
  effectiveRisk(
    rawRisk: number,
    agentId: string,
    domain?: string
  ): number {
    const trust = this.computeTrust(agentId, domain);
    const trustDiscount = (trust - 0.5) * this.influence;
    const adjusted = rawRisk * (1.0 - trustDiscount);
    return Math.max(0.0, Math.min(1.0, adjusted));
  }

  /**
   * Record a successful action for an agent.
   */
  recordSuccess(options: {
    agentId: string;
    actionName: string;
    domain?: string;
    riskScore?: number;
  }): void {
    const {
      agentId,
      actionName,
      domain = "general",
      riskScore = 0.5,
    } = options;
    const profile = this.getProfile(agentId);

    const record: TrustRecord = {
      timestamp: new Date(),
      actionName,
      domain,
      outcome: "success",
      riskScore,
    };
    profile.history.push(record);
    profile.lastActionAt = new Date();
    profile.overallScore = this.computeTrust(agentId);

    if (domain) {
      profile.domainScores[domain] = this.computeTrust(agentId, domain);
    }
    this._save();
  }

  /**
   * Record a denied action for an agent.
   */
  recordDenial(options: {
    agentId: string;
    actionName: string;
    domain?: string;
    riskScore?: number;
  }): void {
    const {
      agentId,
      actionName,
      domain = "general",
      riskScore = 0.5,
    } = options;
    const profile = this.getProfile(agentId);

    const record: TrustRecord = {
      timestamp: new Date(),
      actionName,
      domain,
      outcome: "denied",
      riskScore,
    };
    profile.history.push(record);
    profile.lastActionAt = new Date();
    this._save();
  }

  /**
   * Record a security incident for an agent.
   */
  recordIncident(options: {
    agentId: string;
    actionName?: string;
    domain?: string;
    severity?: string;
    description?: string;
  }): void {
    const {
      agentId,
      actionName = "",
      domain = "general",
    } = options;
    const profile = this.getProfile(agentId);
    profile.incidents += 1;

    const record: TrustRecord = {
      timestamp: new Date(),
      actionName,
      domain,
      outcome: "incident",
      riskScore: 1.0,
    };
    profile.history.push(record);
    profile.overallScore = this.computeTrust(agentId);
    this._save();
  }

  /**
   * Instantly revoke all trust for an agent.
   */
  revoke(agentId: string): void {
    const profile = this.getProfile(agentId);
    profile.overallScore = 0.0;
    profile.domainScores = {};
    profile.incidents += 3; // heavy penalty
    this._save();
  }

  // -- persistence -------------------------------------------------------

  private _save(): void {
    if (!this.storagePath) return;

    const dir = dirname(this.storagePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    const data: Record<string, unknown> = {};
    for (const [agentId, profile] of this._profiles) {
      data[agentId] = {
        overall_score: profile.overallScore,
        domain_scores: profile.domainScores,
        incidents: profile.incidents,
        created_at: profile.createdAt.toISOString(),
        last_action_at: profile.lastActionAt?.toISOString() ?? null,
        history_count: profile.history.length,
      };
    }

    writeFileSync(this.storagePath, JSON.stringify(data, null, 2), "utf-8");
  }

  private _load(): void {
    if (!this.storagePath || !existsSync(this.storagePath)) return;

    const raw = readFileSync(this.storagePath, "utf-8");
    const data = JSON.parse(raw) as Record<
      string,
      {
        overall_score?: number;
        domain_scores?: Record<string, number>;
        incidents?: number;
        created_at?: string;
        last_action_at?: string | null;
      }
    >;

    for (const [agentId, info] of Object.entries(data)) {
      this._profiles.set(agentId, {
        agentId,
        overallScore: info.overall_score ?? this.initialScore,
        domainScores: info.domain_scores ?? {},
        history: [],
        incidents: info.incidents ?? 0,
        createdAt: info.created_at
          ? new Date(info.created_at)
          : new Date(),
        lastActionAt: info.last_action_at
          ? new Date(info.last_action_at)
          : undefined,
      });
    }
  }
}
