/**
 * Pluggable audit backend abstraction.
 *
 * Defines the AuditBackend interface and provides two implementations:
 *
 * 1. LegacyBackend -- wraps the existing AuditLogger (default).
 * 2. TrailProofBackend -- delegates to TrailProof for tamper-evident event logging.
 *
 * The backend is selected via `audit.backend` in attesta.yaml:
 *
 *   audit:
 *     backend: trailproof  # or "legacy" (default)
 *     path: events.jsonl
 *     tenantId: my-org
 */

import type { ActionContext, ApprovalResult } from "./types.js";
import { Verdict } from "./types.js";
import {
  AuditLogger,
  buildEntry,
  type AuditEntryData,
  type ChainVerification,
} from "./audit.js";

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

/**
 * Pluggable audit storage backend.
 *
 * Any object implementing this interface can serve as an audit backend.
 */
export interface AuditBackend {
  /** Persist an audit record and return a unique entry ID. */
  log(ctx: ActionContext, result: ApprovalResult): Promise<string>;

  /** Verify chain integrity. Returns verification result. */
  verify(): ChainVerification;

  /** Return entries matching the supplied filters. */
  query(filters?: Record<string, unknown>): unknown[];
}

// ---------------------------------------------------------------------------
// Legacy backend (wraps existing AuditLogger)
// ---------------------------------------------------------------------------

/**
 * Wraps the existing AuditLogger.
 *
 * This is the default backend when no `audit.backend` is configured.
 * Preserves full backward compatibility with the existing JSONL audit log.
 */
export class LegacyBackend implements AuditBackend {
  private readonly _logger: AuditLogger;

  constructor(path: string = ".attesta/audit.jsonl") {
    this._logger = new AuditLogger(path);
  }

  async log(ctx: ActionContext, result: ApprovalResult): Promise<string> {
    return this._logger.log(ctx, result);
  }

  verify(): ChainVerification {
    return this._logger.verifyChain();
  }

  query(filters?: Record<string, unknown>): AuditEntryData[] {
    return this._logger.query(filters ?? {});
  }

  findRubberStamps(options?: {
    maxReviewSeconds?: number;
    minRisk?: string;
  }): AuditEntryData[] {
    return this._logger.findRubberStamps(options);
  }
}

// ---------------------------------------------------------------------------
// TrailProof backend
// ---------------------------------------------------------------------------

/**
 * Delegates audit logging to TrailProof.
 *
 * Requires: `npm install @kyberonai/trailproof`
 *
 * Maps Attesta audit fields to TrailProof's 10-field event envelope:
 * - `agentId` → `actorId`
 * - `sessionId` → `sessionId`
 * - `tenantId` from config → `tenantId`
 * - Event type: `attesta.approval.{verdict}`
 * - All other Attesta-specific fields → `payload`
 */
export class TrailProofBackend implements AuditBackend {
  private readonly _tp: unknown;
  private readonly _tenantId: string;

  constructor(options: {
    path?: string;
    tenantId?: string;
    hmacKey?: string;
  } = {}) {
    const path = options.path ?? ".attesta/audit.jsonl";
    const tenantId = options.tenantId ?? "default";
    const hmacKey = options.hmacKey;

    this._tenantId = tenantId;

    // Dynamic import to keep trailproof optional
    let Trailproof: unknown;
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      Trailproof = require("@kyberonai/trailproof").Trailproof;
    } catch {
      throw new Error(
        "TrailProof is required for the trailproof audit backend. " +
          "Install with: npm install @kyberonai/trailproof"
      );
    }

    const tpOptions: Record<string, unknown> = {
      store: "jsonl",
      path,
    };
    if (hmacKey != null) {
      tpOptions.hmacKey = hmacKey;
    }

    this._tp = new (Trailproof as new (opts: Record<string, unknown>) => unknown)(
      tpOptions
    ) as Record<string, unknown>;
  }

  async log(ctx: ActionContext, result: ApprovalResult): Promise<string> {
    const entry = buildEntry(ctx, result);

    const verdictStr =
      typeof result.verdict === "string" ? result.verdict : String(result.verdict);
    const eventType = `attesta.approval.${verdictStr}`;

    // All Attesta-specific fields go into the opaque payload
    const payload: Record<string, unknown> = {
      actionName: entry.actionName,
      actionDescription: entry.actionDescription,
      riskScore: entry.riskScore,
      riskLevel: entry.riskLevel,
      challengeType: entry.challengeType,
      challengePassed: entry.challengePassed,
      approverIds: entry.approverIds,
      verdict: entry.verdict,
      reviewDurationSeconds: entry.reviewDurationSeconds,
      minReviewMet: entry.minReviewMet,
      interceptedAt: entry.interceptedAt,
      decidedAt: entry.decidedAt,
      executedAt: entry.executedAt,
      environment: entry.environment,
      metadata: entry.metadata,
    };

    const tp = this._tp as Record<string, (...args: unknown[]) => unknown>;
    const event = tp.emit({
      eventType,
      actorId: ctx.agentId ?? "unknown",
      tenantId: this._tenantId,
      payload,
      sessionId: ctx.sessionId ?? undefined,
    }) as { eventId: string };

    return event.eventId;
  }

  verify(): ChainVerification {
    const tp = this._tp as Record<string, () => unknown>;
    const result = tp.verify() as {
      intact: boolean;
      total: number;
      broken: number[];
    };
    return {
      intact: result.intact,
      totalEntries: result.total,
      brokenLinkIndices: [...result.broken],
    };
  }

  query(filters?: Record<string, unknown>): unknown[] {
    const tp = this._tp as Record<string, (f: unknown) => unknown>;
    const tpFilters: Record<string, unknown> = {};

    if (filters?.agentId != null) {
      tpFilters.actorId = filters.agentId;
    }
    if (filters?.limit != null) {
      tpFilters.limit = filters.limit;
    }

    const result = tp.query(tpFilters) as { events: unknown[] };
    return result.events;
  }

  flush(): void {
    const tp = this._tp as Record<string, () => void>;
    tp.flush();
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an audit backend by name.
 *
 * @param backend - "legacy" (default) or "trailproof"
 * @param options - Backend configuration options
 */
export function createBackend(
  backend: string = "legacy",
  options: {
    path?: string;
    tenantId?: string;
    hmacKey?: string;
  } = {}
): AuditBackend {
  const normalized = backend.trim().toLowerCase();

  if (normalized === "trailproof") {
    return new TrailProofBackend(options);
  } else if (
    normalized === "legacy" ||
    normalized === "default" ||
    normalized === ""
  ) {
    return new LegacyBackend(options.path);
  } else {
    throw new Error(
      `Unknown audit backend: "${backend}". Use "legacy" or "trailproof".`
    );
  }
}
