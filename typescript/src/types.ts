/**
 * Core type definitions for attesta.
 *
 * This module defines the foundational data structures, enums, and interfaces
 * that all other modules depend on. It is intentionally dependency-free
 * (no imports from other attesta modules) so it can be imported anywhere
 * without circular-import issues.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/**
 * Discrete risk classification derived from a continuous 0-1 score.
 */
export const RiskLevel = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type RiskLevel = (typeof RiskLevel)[keyof typeof RiskLevel];

/**
 * Map a continuous risk score in [0, 1] to a discrete level.
 */
export function riskLevelFromScore(score: number): RiskLevel {
  if (score < 0.0 || score > 1.0) {
    throw new RangeError(`Risk score must be in [0, 1], got ${score}`);
  }
  if (score < 0.3) return RiskLevel.LOW;
  if (score < 0.6) return RiskLevel.MEDIUM;
  if (score < 0.8) return RiskLevel.HIGH;
  return RiskLevel.CRITICAL;
}

/**
 * The outcome of a attesta review.
 */
export const Verdict = {
  APPROVED: "approved",
  DENIED: "denied",
  MODIFIED: "modified",
  TIMED_OUT: "timed_out",
  ESCALATED: "escalated",
} as const;

export type Verdict = (typeof Verdict)[keyof typeof Verdict];

/**
 * The kind of verification challenge presented to the operator.
 */
export const ChallengeType = {
  AUTO_APPROVE: "auto_approve",
  CONFIRM: "confirm",
  QUIZ: "quiz",
  TEACH_BACK: "teach_back",
  MULTI_PARTY: "multi_party",
} as const;

export type ChallengeType = (typeof ChallengeType)[keyof typeof ChallengeType];

// ---------------------------------------------------------------------------
// Data interfaces
// ---------------------------------------------------------------------------

/**
 * All information about a single function invocation under review.
 *
 * The gate decorator builds this automatically from the wrapped call,
 * but callers may also construct one manually for programmatic use.
 */
export interface ActionContext {
  /** The name of the function being invoked. */
  functionName: string;

  /** Positional arguments passed to the function. */
  args: readonly unknown[];

  /** Keyword/named arguments passed to the function. */
  kwargs: Record<string, unknown>;

  /** Documentation string for the function, if available. */
  functionDoc?: string;

  /** Caller-supplied risk hints (e.g. { pii: true, destructive: true }). */
  hints: Record<string, unknown>;

  /** Identifier of the AI agent making the call. */
  agentId?: string;

  /** Session identifier for grouping related actions. */
  sessionId?: string;

  /** Deployment environment (e.g. "development", "production"). */
  environment: string;

  /** Timestamp of when the action was intercepted. */
  timestamp: Date;

  /** Source code of the function, if available. */
  sourceCode?: string;

  /** Arbitrary metadata attached to the context. */
  metadata: Record<string, unknown>;
}

/**
 * Create an ActionContext with sensible defaults.
 */
export function createActionContext(
  options: Partial<ActionContext> & Pick<ActionContext, "functionName">
): ActionContext {
  return {
    args: [],
    kwargs: {},
    hints: {},
    environment: "development",
    timestamp: new Date(),
    metadata: {},
    ...options,
  };
}

/**
 * Human-readable one-liner describing the call.
 */
export function describeAction(ctx: ActionContext): string {
  const parts: string[] = ctx.args.map((a) => JSON.stringify(a));
  for (const [k, v] of Object.entries(ctx.kwargs)) {
    parts.push(`${k}=${JSON.stringify(v)}`);
  }
  return `${ctx.functionName}(${parts.join(", ")})`;
}

/**
 * A single contributing factor to an overall risk score.
 */
export interface RiskFactor {
  /** Name of the risk factor (e.g. "function_name", "arguments"). */
  name: string;

  /** Weighted contribution of this factor to the total score. */
  contribution: number;

  /** Human-readable description of the factor. */
  description: string;

  /** Optional evidence string (e.g. the matched pattern). */
  evidence?: string;
}

/**
 * The result of evaluating the risk of an action.
 */
export interface RiskAssessment {
  /** Continuous risk score in [0.0, 1.0]. */
  score: number;

  /** Discrete risk level derived from the score. */
  level: RiskLevel;

  /** Individual factors that contributed to the score. */
  factors: RiskFactor[];

  /** Name of the scorer that produced this assessment. */
  scorerName: string;
}

/**
 * Create a RiskAssessment, validating the score range.
 */
export function createRiskAssessment(
  options: Partial<RiskAssessment> &
    Pick<RiskAssessment, "score" | "level">
): RiskAssessment {
  if (options.score < 0.0 || options.score > 1.0) {
    throw new RangeError(
      `Risk score must be in [0, 1], got ${options.score}`
    );
  }
  return {
    factors: [],
    scorerName: "default",
    ...options,
  };
}

/**
 * Outcome of a verification challenge.
 */
export interface ChallengeResult {
  /** Whether the operator passed the challenge. */
  passed: boolean;

  /** The type of challenge that was presented. */
  challengeType: ChallengeType;

  /** Identifier of the person who responded. */
  responder: string;

  /** How long the challenge took to complete, in seconds. */
  responseTimeSeconds: number;

  /** Number of questions asked (for quiz/teach-back challenges). */
  questionsAsked: number;

  /** Number of questions answered correctly. */
  questionsCorrect: number;

  /** Additional challenge-specific details. */
  details: Record<string, unknown>;
}

/**
 * Create a ChallengeResult with sensible defaults.
 */
export function createChallengeResult(
  options: Partial<ChallengeResult> &
    Pick<ChallengeResult, "passed" | "challengeType">
): ChallengeResult {
  return {
    responder: "default",
    responseTimeSeconds: 0,
    questionsAsked: 0,
    questionsCorrect: 0,
    details: {},
    ...options,
  };
}

/**
 * Full audit-ready record of a attesta decision.
 */
export interface ApprovalResult {
  /** The final decision. */
  verdict: Verdict;

  /** Risk assessment that informed the decision. */
  riskAssessment: RiskAssessment;

  /** Challenge result, if a challenge was presented. */
  challengeResult?: ChallengeResult;

  /** List of approver identifiers. */
  approvers: string[];

  /** Total review wall-clock time in seconds. */
  reviewTimeSeconds: number;

  /** Unique identifier for the audit log entry. */
  auditEntryId?: string;

  /** When the decision was made. */
  timestamp: Date;

  /** Description of modifications (when verdict is MODIFIED). */
  modification?: string;
}

/**
 * Create an ApprovalResult with sensible defaults.
 */
export function createApprovalResult(
  options: Partial<ApprovalResult> &
    Pick<ApprovalResult, "verdict" | "riskAssessment">
): ApprovalResult {
  return {
    approvers: [],
    reviewTimeSeconds: 0,
    timestamp: new Date(),
    ...options,
  };
}

// ---------------------------------------------------------------------------
// Protocols (structural interfaces)
// ---------------------------------------------------------------------------

/**
 * Anything that can assign a 0-1 risk score to an action.
 */
export interface RiskScorer {
  /** Score the risk of the given action context. Returns a value in [0, 1]. */
  score(ctx: ActionContext): number;

  /** Human-readable name for this scorer. */
  readonly name: string;
}

/**
 * Anything that can present a verification challenge.
 */
export interface ChallengeProtocol {
  /** Present a challenge to the operator and return the result. */
  present(ctx: ActionContext, risk: RiskAssessment): Promise<ChallengeResult>;

  /** The type of challenge this protocol presents. */
  readonly challengeType: ChallengeType;
}

/**
 * UI / UX layer for presenting gates to the operator.
 */
export interface Renderer {
  /** Present an approval prompt and return the verdict. */
  renderApproval(ctx: ActionContext, risk: RiskAssessment): Promise<Verdict>;

  /** Present a challenge and return the result. */
  renderChallenge(
    ctx: ActionContext,
    risk: RiskAssessment,
    challengeType: ChallengeType
  ): Promise<ChallengeResult>;

  /** Display an informational message. */
  renderInfo(message: string): Promise<void>;

  /** Notify that an action was auto-approved. */
  renderAutoApproved(ctx: ActionContext, risk: RiskAssessment): Promise<void>;
}

/**
 * Anything that can validate a teach-back explanation.
 */
export interface TeachBackValidatorProtocol {
  /** Validate explanation and return { passed, notes }. */
  validate(
    explanation: string,
    context: ActionContext
  ): Promise<{ passed: boolean; notes: string }>;
}

/**
 * Anything that can persist an approval record for auditing.
 */
export interface AuditLoggerProtocol {
  /** Persist the result and return a unique audit-entry ID. */
  log(ctx: ActionContext, result: ApprovalResult): Promise<string>;
}
