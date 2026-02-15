/**
 * Hash-chained audit logging system.
 *
 * Every attesta decision is recorded as an AuditEntry and appended
 * to a JSONL file. Entries are linked by a SHA-256 hash chain: each entry's
 * chainHash is the SHA-256 digest of the previous entry's hash
 * concatenated with the current entry's canonical JSON representation. This
 * makes post-hoc tampering detectable via verifyChain().
 *
 * Uses Node.js crypto for SHA-256 with Web Crypto API fallback for edge runtimes.
 */

import { createHash, randomUUID } from "node:crypto";
import {
  readFileSync,
  appendFileSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import { dirname } from "node:path";

import {
  type ActionContext,
  type ApprovalResult,
  type AuditLoggerProtocol,
  Verdict,
  describeAction,
} from "./types.js";

// ---------------------------------------------------------------------------
// SHA-256 hashing (Node.js with Web Crypto fallback)
// ---------------------------------------------------------------------------

/**
 * Synchronous SHA-256 using Node.js crypto.
 * This is the fast path used in the main implementation.
 */
function sha256Sync(input: string): string {
  return createHash("sha256").update(input, "utf-8").digest("hex");
}

/**
 * Async SHA-256 with Web Crypto API fallback for edge runtimes.
 * On Node.js this simply delegates to the sync version.
 */
async function sha256Async(input: string): Promise<string> {
  try {
    return sha256Sync(input);
  } catch {
    // Web Crypto API fallback (e.g. Cloudflare Workers, Deno)
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", data);
    const hashArray = new Uint8Array(hashBuffer);
    return Array.from(hashArray)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** SHA-256 zero hash for the first entry in the chain. */
const GENESIS_HASH = "0".repeat(64);

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/**
 * A single, immutable audit record for one attesta decision.
 * All fields are plain, JSON-serialisable types.
 */
export interface AuditEntryData {
  /** Unique identifier for this entry. */
  entryId: string;

  /** SHA-256 chain hash linking to the previous entry. */
  chainHash: string;

  /** Hash of the previous entry in the chain. */
  previousHash: string;

  /** Name of the action that was reviewed. */
  actionName: string;

  /** Human-readable description of the action call. */
  actionDescription: string;

  /** The agent that requested the action. */
  agentId: string;

  /** Continuous risk score in [0, 1]. */
  riskScore: number;

  /** Discrete risk level (e.g. "low", "high"). */
  riskLevel: string;

  /** Type of challenge presented (e.g. "confirm", "quiz"). */
  challengeType: string;

  /** Whether the challenge was passed (null if no challenge). */
  challengePassed: boolean | null;

  /** List of approver identifiers. */
  approverIds: string[];

  /** The final verdict (e.g. "approved", "denied"). */
  verdict: string;

  /** How long the review took in seconds. */
  reviewDurationSeconds: number;

  /** Whether the minimum review time was met. */
  minReviewMet: boolean;

  /** ISO-8601 timestamp when the action was intercepted. */
  interceptedAt: string;

  /** ISO-8601 timestamp when the decision was made. */
  decidedAt: string;

  /** ISO-8601 timestamp when the action was executed (empty if denied). */
  executedAt: string;

  /** Session identifier. */
  sessionId: string;

  /** Deployment environment. */
  environment: string;

  /** Arbitrary metadata. */
  metadata: Record<string, unknown>;
}

/**
 * Create an AuditEntryData with sensible defaults.
 */
export function createAuditEntry(
  options: Partial<AuditEntryData> = {}
): AuditEntryData {
  return {
    entryId: randomUUID().replace(/-/g, ""),
    chainHash: "",
    previousHash: "",
    actionName: "",
    actionDescription: "",
    agentId: "",
    riskScore: 0,
    riskLevel: "",
    challengeType: "",
    challengePassed: null,
    approverIds: [],
    verdict: "",
    reviewDurationSeconds: 0,
    minReviewMet: true,
    interceptedAt: "",
    decidedAt: "",
    executedAt: "",
    sessionId: "",
    environment: "",
    metadata: {},
    ...options,
  };
}

/**
 * Convert an AuditEntryData to a canonical JSON string (sorted keys, compact).
 */
export function auditEntryToJson(entry: AuditEntryData): string {
  return JSON.stringify(sortObject(entry));
}

/**
 * Parse an AuditEntryData from a JSON string.
 */
export function auditEntryFromJson(json: string): AuditEntryData {
  const data = JSON.parse(json) as Record<string, unknown>;
  return createAuditEntry(data as Partial<AuditEntryData>);
}

/**
 * Compute the hashable dict (all fields except chainHash) as canonical JSON.
 */
function hashableJson(entry: AuditEntryData): string {
  const copy = { ...entry };
  delete (copy as Record<string, unknown>)["chainHash"];
  return JSON.stringify(sortObject(copy));
}

/**
 * Compute the SHA-256 chain hash for an entry.
 *
 * hash = sha256(previousHash + canonical_json_without_chain_hash)
 */
export function computeEntryHash(
  entry: AuditEntryData,
  previousHash: string
): string {
  const payload = previousHash + hashableJson(entry);
  return sha256Sync(payload);
}

/**
 * Async version of computeEntryHash for edge runtimes.
 */
export async function computeEntryHashAsync(
  entry: AuditEntryData,
  previousHash: string
): Promise<string> {
  const payload = previousHash + hashableJson(entry);
  return sha256Async(payload);
}

// ---------------------------------------------------------------------------
// Builder: ActionContext + ApprovalResult -> AuditEntryData
// ---------------------------------------------------------------------------

/**
 * Populate an AuditEntryData from core types produced during a gate evaluation.
 */
export function buildEntry(
  ctx: ActionContext,
  result: ApprovalResult,
  options?: { minReviewSeconds?: number }
): AuditEntryData {
  const nowIso = new Date().toISOString();
  const minReviewSeconds = options?.minReviewSeconds ?? 0;

  let challengeType = "";
  let challengePassed: boolean | null = null;
  if (result.challengeResult != null) {
    challengeType = result.challengeResult.challengeType;
    challengePassed = result.challengeResult.passed;
  }

  return createAuditEntry({
    actionName: ctx.functionName,
    actionDescription: describeAction(ctx),
    agentId: ctx.agentId ?? "",
    riskScore: result.riskAssessment.score,
    riskLevel: result.riskAssessment.level,
    challengeType,
    challengePassed,
    approverIds: [...result.approvers],
    verdict: result.verdict,
    reviewDurationSeconds: result.reviewTimeSeconds,
    minReviewMet: result.reviewTimeSeconds >= minReviewSeconds,
    interceptedAt: ctx.timestamp.toISOString(),
    decidedAt: result.timestamp.toISOString(),
    executedAt: result.verdict === Verdict.APPROVED ? nowIso : "",
    sessionId: ctx.sessionId ?? "",
    environment: ctx.environment,
    metadata: { ...ctx.metadata },
  });
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/**
 * Verification result from verifyChain().
 */
export interface ChainVerification {
  /** Whether the entire chain is intact. */
  intact: boolean;

  /** Total number of entries checked. */
  totalEntries: number;

  /** 0-based indices of broken links. */
  brokenLinkIndices: number[];
}

/**
 * Query filters for searching audit entries.
 */
export interface AuditQueryFilters {
  /** Exact match on risk level. */
  riskLevel?: string;

  /** Exact match on verdict. */
  verdict?: string;

  /** Exact match on agent ID. */
  agentId?: string;

  /** Exact match on session ID. */
  sessionId?: string;

  /** Exact match on environment. */
  environment?: string;

  /** Exact match on action name. */
  actionName?: string;

  /** Exact match on challenge type. */
  challengeType?: string;

  /** Match on challenge passed status. */
  challengePassed?: boolean;

  /** Entries on or after this date. */
  fromDate?: Date | string;

  /** Entries on or before this date. */
  toDate?: Date | string;
}

/**
 * Hash-chained JSONL audit logger.
 *
 * Each call to log() appends a new AuditEntry to the JSONL file with its
 * chainHash computed from the previous entry's hash. The chain can be
 * verified at any time with verifyChain().
 */
export class AuditLogger implements AuditLoggerProtocol {
  readonly path: string;
  private _lastHash: string = GENESIS_HASH;
  private _entryCount: number = 0;

  constructor(path: string = ".attesta/audit.jsonl") {
    this.path = path;

    // Resume from existing log if present.
    if (existsSync(this.path)) {
      this._resumeChain();
    }
  }

  // -- Public API --------------------------------------------------------

  /**
   * Persist an audit entry built from ActionContext + ApprovalResult
   * and return its entryId. Satisfies the AuditLoggerProtocol interface.
   */
  async log(ctx: ActionContext, result: ApprovalResult): Promise<string> {
    const entry = buildEntry(ctx, result);
    this._append(entry);
    return entry.entryId;
  }

  /**
   * Directly log a pre-built AuditEntryData.
   * Useful for programmatic auditing outside the gate pipeline.
   */
  logEntry(entry: AuditEntryData): void {
    this._append(entry);
  }

  /**
   * Verify the integrity of the entire audit chain.
   */
  verifyChain(): ChainVerification {
    if (!existsSync(this.path)) {
      return { intact: true, totalEntries: 0, brokenLinkIndices: [] };
    }

    const broken: number[] = [];
    let previousHash = GENESIS_HASH;
    let total = 0;

    const content = readFileSync(this.path, "utf-8");
    const lines = content.split("\n");

    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx].trim();
      if (!line) continue;
      total++;

      let entry: AuditEntryData;
      try {
        entry = auditEntryFromJson(line);
      } catch {
        broken.push(idx);
        continue;
      }

      const expected = computeEntryHash(entry, previousHash);
      if (entry.chainHash !== expected) {
        broken.push(idx);
      }

      // Advance the chain regardless so we can detect *which* links
      // are broken rather than cascading all subsequent entries.
      previousHash = entry.chainHash;
    }

    return {
      intact: broken.length === 0,
      totalEntries: total,
      brokenLinkIndices: broken,
    };
  }

  /**
   * Return entries matching all supplied filters.
   */
  query(filters: AuditQueryFilters): AuditEntryData[] {
    if (!existsSync(this.path)) {
      return [];
    }

    // Normalize enum values if caller passes objects with .value
    const normalizedFilters = { ...filters };
    for (const key of [
      "riskLevel",
      "verdict",
      "challengeType",
    ] as const) {
      const val = normalizedFilters[key];
      if (val != null && typeof val === "object" && "value" in val) {
        normalizedFilters[key] = (val as { value: string }).value;
      }
    }

    const fromDt = parseDateFilter(normalizedFilters.fromDate);
    const toDt = parseDateFilter(normalizedFilters.toDate);

    const results: AuditEntryData[] = [];
    const content = readFileSync(this.path, "utf-8");
    const lines = content.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let entry: AuditEntryData;
      try {
        entry = auditEntryFromJson(trimmed);
      } catch {
        continue;
      }

      if (matchesFilters(entry, normalizedFilters, fromDt, toDt)) {
        results.push(entry);
      }
    }

    return results;
  }

  /**
   * Find suspiciously fast approvals on high-risk actions ("rubber stamps").
   */
  findRubberStamps(options?: {
    maxReviewSeconds?: number;
    minRisk?: string;
  }): AuditEntryData[] {
    const maxReviewSeconds = options?.maxReviewSeconds ?? 5.0;
    const minRisk = options?.minRisk ?? "high";
    const riskOrder = riskLevelOrder();
    const minRiskIdx = riskOrder[minRisk.toLowerCase()] ?? 2;

    if (!existsSync(this.path)) {
      return [];
    }

    const stamps: AuditEntryData[] = [];
    const content = readFileSync(this.path, "utf-8");
    const lines = content.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let entry: AuditEntryData;
      try {
        entry = auditEntryFromJson(trimmed);
      } catch {
        continue;
      }

      if (entry.verdict !== Verdict.APPROVED) continue;
      const entryRiskIdx = riskOrder[entry.riskLevel.toLowerCase()] ?? -1;
      if (entryRiskIdx < minRiskIdx) continue;
      if (entry.reviewDurationSeconds > maxReviewSeconds) continue;
      stamps.push(entry);
    }

    return stamps;
  }

  // -- Internals ---------------------------------------------------------

  private _append(entry: AuditEntryData): void {
    entry.previousHash = this._lastHash;
    entry.chainHash = computeEntryHash(entry, this._lastHash);
    this._lastHash = entry.chainHash;
    this._entryCount++;

    const dir = dirname(this.path);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    appendFileSync(this.path, auditEntryToJson(entry) + "\n", "utf-8");
  }

  private _resumeChain(): void {
    let count = 0;
    let lastHash = GENESIS_HASH;

    const content = readFileSync(this.path, "utf-8");
    const lines = content.split("\n");

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      count++;

      try {
        const data = JSON.parse(trimmed) as Record<string, unknown>;
        if (typeof data.chainHash === "string") {
          lastHash = data.chainHash;
        }
      } catch {
        // Skip malformed lines during resume
      }
    }

    this._lastHash = lastHash;
    this._entryCount = count;
  }
}

// ---------------------------------------------------------------------------
// Module-level helpers
// ---------------------------------------------------------------------------

function parseDateFilter(
  value: Date | string | undefined
): Date | undefined {
  if (value == null) return undefined;
  if (value instanceof Date) return value;
  if (typeof value === "string") {
    const d = new Date(value);
    return isNaN(d.getTime()) ? undefined : d;
  }
  return undefined;
}

function riskLevelOrder(): Record<string, number> {
  return {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3,
  };
}

const SIMPLE_FILTER_KEYS = [
  "riskLevel",
  "verdict",
  "agentId",
  "sessionId",
  "environment",
  "actionName",
  "challengeType",
] as const;

function matchesFilters(
  entry: AuditEntryData,
  filters: AuditQueryFilters,
  fromDt: Date | undefined,
  toDt: Date | undefined
): boolean {
  for (const key of SIMPLE_FILTER_KEYS) {
    const filterVal = filters[key];
    if (filterVal != null) {
      if ((entry as unknown as Record<string, unknown>)[key] !== filterVal) {
        return false;
      }
    }
  }

  if (filters.challengePassed != null) {
    if (entry.challengePassed !== filters.challengePassed) {
      return false;
    }
  }

  // Date range filters (based on interceptedAt).
  if (fromDt || toDt) {
    const entryDt = parseDateFilter(entry.interceptedAt);
    if (!entryDt) return false;
    if (fromDt && entryDt < fromDt) return false;
    if (toDt && entryDt > toDt) return false;
  }

  return true;
}

/**
 * Recursively sort object keys for canonical JSON output.
 */
function sortObject(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(sortObject);
  if (typeof obj === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
      sorted[key] = sortObject(
        (obj as Record<string, unknown>)[key]
      );
    }
    return sorted;
  }
  return obj;
}
