/**
 * Attesta decorator and Attesta orchestrator.
 *
 * This module provides the `gate()` function -- the primary user-facing API
 * for protecting function calls -- and the `Attesta` class that orchestrates the
 * full risk-scoring -> challenge-selection -> verification -> audit pipeline.
 */

import { randomUUID } from "node:crypto";

import {
  type ActionContext,
  type ApprovalResult,
  type AuditLoggerProtocol,
  type ChallengeResult,
  ChallengeType,
  type Renderer,
  type RiskAssessment,
  type RiskScorer,
  RiskLevel,
  Verdict,
  createActionContext,
  createApprovalResult,
  createChallengeResult,
  createRiskAssessment,
  describeAction,
  riskLevelFromScore,
} from "./types.js";

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

/**
 * Raised when a gated function call is denied by the reviewer.
 */
export class AttestaDenied extends Error {
  readonly result?: ApprovalResult;

  constructor(
    message: string = "Action denied by attesta",
    options?: { result?: ApprovalResult }
  ) {
    super(message);
    this.name = "AttestaDenied";
    this.result = options?.result;
  }
}

// ---------------------------------------------------------------------------
// Default implementations (used when no external components are supplied)
// ---------------------------------------------------------------------------

class DefaultRiskScorerInternal implements RiskScorer {
  get name(): string {
    return "default";
  }

  score(ctx: ActionContext): number {
    let base = 0.1;
    if (ctx.environment === "production") base += 0.3;
    if (ctx.hints["production"]) base += 0.2;
    if (ctx.hints["destructive"]) base += 0.3;
    if (ctx.hints["pii"]) base += 0.2;
    return Math.min(base, 1.0);
  }
}

class DefaultRenderer implements Renderer {
  async renderApproval(
    _ctx: ActionContext,
    _risk: RiskAssessment
  ): Promise<Verdict> {
    return Verdict.APPROVED;
  }

  async renderChallenge(
    _ctx: ActionContext,
    _risk: RiskAssessment,
    challengeType: ChallengeType
  ): Promise<ChallengeResult> {
    return createChallengeResult({
      passed: true,
      challengeType,
      responder: "auto",
    });
  }

  async renderInfo(message: string): Promise<void> {
    // eslint-disable-next-line no-console
    console.log(`[attesta] ${message}`);
  }

  async renderAutoApproved(
    ctx: ActionContext,
    risk: RiskAssessment
  ): Promise<void> {
    // eslint-disable-next-line no-console
    console.debug(
      `[attesta] Auto-approved ${ctx.functionName} (risk=${risk.score.toFixed(2)})`
    );
  }
}

class DefaultAuditLogger implements AuditLoggerProtocol {
  async log(ctx: ActionContext, result: ApprovalResult): Promise<string> {
    const entryId = randomUUID().replace(/-/g, "").slice(0, 12);
    // eslint-disable-next-line no-console
    console.log(
      `[audit:${entryId}] ${describeAction(ctx)} -> ${result.verdict} (risk=${result.riskAssessment.score.toFixed(2)})`
    );
    return entryId;
  }
}

// ---------------------------------------------------------------------------
// Policy helpers
// ---------------------------------------------------------------------------

/** Default mapping from risk level to challenge type. */
const DEFAULT_CHALLENGE_MAP: Record<RiskLevel, ChallengeType> = {
  [RiskLevel.LOW]: ChallengeType.AUTO_APPROVE,
  [RiskLevel.MEDIUM]: ChallengeType.CONFIRM,
  [RiskLevel.HIGH]: ChallengeType.QUIZ,
  [RiskLevel.CRITICAL]: ChallengeType.MULTI_PARTY,
} as const;

function selectChallenge(
  risk: RiskAssessment,
  challengeMap?: Partial<Record<RiskLevel, ChallengeType>>
): ChallengeType {
  const mapping = challengeMap ?? DEFAULT_CHALLENGE_MAP;
  return mapping[risk.level] ?? ChallengeType.CONFIRM;
}

// ---------------------------------------------------------------------------
// Attesta options
// ---------------------------------------------------------------------------

/**
 * Options for configuring an Attesta instance.
 */
export interface AttestaOptions {
  /** Risk scorer to use for evaluating actions. */
  riskScorer?: RiskScorer;

  /** Renderer for presenting challenges and approvals. */
  renderer?: Renderer;

  /** Audit logger for recording decisions. */
  auditLogger?: AuditLoggerProtocol;

  /** Override the default risk-level to challenge-type mapping. */
  challengeMap?: Partial<Record<RiskLevel, ChallengeType>>;

  /** Minimum wall-clock time the review must take (seconds). */
  minReviewSeconds?: number;

  /** Explicitly override the risk level (bypasses the scorer). */
  riskOverride?: RiskLevel;

  /** Extra hints merged into the ActionContext.hints dict. */
  riskHints?: Record<string, unknown>;

  /** Optional EventBus for lifecycle event notifications. */
  eventBus?: import("./events.js").EventBus;
}

// ---------------------------------------------------------------------------
// Attesta class
// ---------------------------------------------------------------------------

/**
 * Orchestrates the full approval pipeline for a single gated action.
 *
 * Typical lifecycle:
 * ```ts
 * const g = new Attesta({ riskScorer: scorer, renderer, auditLogger: audit });
 * const result = await g.evaluate(ctx);
 * // result.verdict tells you what happened
 * ```
 */
export class Attesta {
  private readonly _scorer: RiskScorer;
  private readonly _renderer: Renderer;
  private readonly _audit: AuditLoggerProtocol;
  private readonly _challengeMap?: Partial<Record<RiskLevel, ChallengeType>>;
  private readonly _minReviewSeconds: number;
  private readonly _riskOverride?: RiskLevel;
  private readonly _riskHints: Record<string, unknown>;
  private readonly _eventBus?: import("./events.js").EventBus;

  constructor(options: AttestaOptions = {}) {
    this._scorer = options.riskScorer ?? new DefaultRiskScorerInternal();
    this._renderer = options.renderer ?? new DefaultRenderer();
    this._audit = options.auditLogger ?? new DefaultAuditLogger();
    this._challengeMap = options.challengeMap;
    this._minReviewSeconds = options.minReviewSeconds ?? 0;
    this._riskOverride = options.riskOverride;
    this._riskHints = options.riskHints ?? {};
    this._eventBus = options.eventBus;
  }

  /**
   * Emit an event if an event bus is configured. No-op otherwise.
   */
  private async _emit(
    eventType: string,
    data: Record<string, unknown>
  ): Promise<void> {
    if (!this._eventBus) return;
    try {
      const { createEvent } = await import("./events.js");
      const event = createEvent(
        eventType as import("./events.js").EventType,
        data
      );
      await this._eventBus.asyncEmit(event);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[attesta] Failed to emit event ${eventType}:`, err);
    }
  }

  /**
   * Run the full approval pipeline and return the result.
   */
  async evaluate(ctx: ActionContext): Promise<ApprovalResult> {
    const reviewStart = performance.now();

    // 1. Merge extra hints.
    if (Object.keys(this._riskHints).length > 0) {
      ctx.hints = { ...ctx.hints, ...this._riskHints };
    }

    // 2. Risk scoring.
    const risk = this._assessRisk(ctx);

    await this._emit("risk_scored", {
      actionName: ctx.functionName,
      riskScore: risk.score,
      riskLevel: risk.level,
    });

    // 3. Select challenge.
    const challengeType = selectChallenge(risk, this._challengeMap);

    // 4. Present challenge / collect verdict.
    let challengeResult: ChallengeResult | undefined;
    let verdict: Verdict;

    if (challengeType === ChallengeType.AUTO_APPROVE) {
      verdict = Verdict.APPROVED;
      await this._renderer.renderAutoApproved(ctx, risk);
    } else {
      await this._emit("challenge_issued", {
        actionName: ctx.functionName,
        challengeType,
        riskLevel: risk.level,
      });
      challengeResult = await this._renderer.renderChallenge(
        ctx,
        risk,
        challengeType
      );
      verdict = challengeResult.passed ? Verdict.APPROVED : Verdict.DENIED;
      await this._emit("challenge_completed", {
        actionName: ctx.functionName,
        challengeType,
        passed: challengeResult.passed,
      });
    }

    // 5. Enforce minimum review time.
    const elapsed = (performance.now() - reviewStart) / 1000;
    const remaining = this._minReviewSeconds - elapsed;
    if (remaining > 0) {
      await new Promise((resolve) =>
        setTimeout(resolve, remaining * 1000)
      );
    }

    const reviewTime =
      Math.round(((performance.now() - reviewStart) / 1000) * 1000) / 1000;

    // 6. Build result.
    const result = createApprovalResult({
      verdict,
      riskAssessment: risk,
      challengeResult,
      reviewTimeSeconds: reviewTime,
    });

    // 6b. Emit verdict event.
    const verdictEvent =
      verdict === Verdict.APPROVED ? "approved" : "denied";
    await this._emit(verdictEvent, {
      actionName: ctx.functionName,
      riskScore: risk.score,
      riskLevel: risk.level,
      verdict,
    });

    // 7. Audit.
    try {
      result.auditEntryId = await this._audit.log(ctx, result);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(
        `[attesta] Audit logging failed for ${describeAction(ctx)}:`,
        err
      );
    }

    if (result.auditEntryId) {
      await this._emit("audit_logged", {
        actionName: ctx.functionName,
        auditEntryId: result.auditEntryId,
        verdict,
      });
    }

    return result;
  }

  // -- internals ---------------------------------------------------------

  private _assessRisk(ctx: ActionContext): RiskAssessment {
    if (this._riskOverride != null) {
      const scoreMap: Record<RiskLevel, number> = {
        [RiskLevel.LOW]: 0.15,
        [RiskLevel.MEDIUM]: 0.45,
        [RiskLevel.HIGH]: 0.7,
        [RiskLevel.CRITICAL]: 0.9,
      };
      const score = scoreMap[this._riskOverride];
      return createRiskAssessment({
        score,
        level: this._riskOverride,
        factors: [
          {
            name: "manual_override",
            contribution: score,
            description: `Risk level manually set to ${this._riskOverride}`,
          },
        ],
        scorerName: "override",
      });
    }

    const rawScore = this._scorer.score(ctx);
    const score = Math.max(0.0, Math.min(1.0, rawScore));
    const level = riskLevelFromScore(score);
    return createRiskAssessment({
      score,
      level,
      scorerName: this._scorer.name,
    });
  }
}

// ---------------------------------------------------------------------------
// gate() decorator / wrapper
// ---------------------------------------------------------------------------

/**
 * Options for the `gate()` decorator/wrapper.
 */
export interface AttestaDecoratorOptions extends AttestaOptions {
  /** Explicit risk level override (e.g. "high" or RiskLevel.HIGH). */
  risk?: RiskLevel;

  /** Dict of hints forwarded to the risk scorer. */
  riskHints?: Record<string, unknown>;

  /** Agent identifier attached to every ActionContext. */
  agentId?: string;

  /** Session identifier attached to every ActionContext. */
  sessionId?: string;

  /** Deployment environment (e.g. "development", "production"). */
  environment?: string;

  /** Extra metadata attached to every ActionContext. */
  metadata?: Record<string, unknown>;
}

/** Internal type for the gate-decorated function property. */
const GATE_SYMBOL = Symbol.for("attesta.gate");

/**
 * Check if a function has been wrapped by `gate()` and retrieve its Attesta instance.
 */
export function getAttesta(fn: unknown): Attesta | undefined {
  if (
    typeof fn === "function" &&
    GATE_SYMBOL in fn
  ) {
    return (fn as Record<symbol, Attesta>)[GATE_SYMBOL];
  }
  return undefined;
}

/**
 * Build an ActionContext from a live function call.
 */
function buildContext(
  fn: (...args: unknown[]) => unknown,
  args: unknown[],
  options: AttestaDecoratorOptions
): ActionContext {
  return createActionContext({
    functionName: fn.name || "anonymous",
    args,
    kwargs: {},
    functionDoc: undefined,
    hints: { ...(options.riskHints ?? {}) },
    agentId: options.agentId,
    sessionId: options.sessionId,
    environment: options.environment ?? "development",
    metadata: { ...(options.metadata ?? {}) },
  });
}

/**
 * Throw a AttestaDenied error for non-approved verdicts.
 */
function throwIfDenied(result: ApprovalResult, description: string): void {
  if (result.verdict === Verdict.DENIED) {
    throw new AttestaDenied(`Action denied: ${description}`, {
      result,
    });
  }
  if (result.verdict === Verdict.TIMED_OUT) {
    throw new AttestaDenied(`Action timed out: ${description}`, {
      result,
    });
  }
  if (result.verdict === Verdict.ESCALATED) {
    throw new AttestaDenied(
      `Action escalated (not yet resolved): ${description}`,
      { result }
    );
  }
}

// Overload signatures for gate():

/**
 * Use as a bare wrapper: `gate(myFunction)` -- wraps with defaults.
 */
export function gate<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>
): (...args: TArgs) => Promise<TReturn>;

/**
 * Use as a configured wrapper: `gate({ risk: "high" })(myFunction)`
 * or `gate({ risk: "high" }, myFunction)`.
 */
export function gate(
  options: AttestaDecoratorOptions
): <TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>
) => (...args: TArgs) => Promise<TReturn>;

/**
 * Use with options and function at once: `gate(options, myFunction)`.
 */
export function gate<TArgs extends unknown[], TReturn>(
  options: AttestaDecoratorOptions,
  fn: (...args: TArgs) => TReturn | Promise<TReturn>
): (...args: TArgs) => Promise<TReturn>;

/**
 * Decorator/wrapper that protects a function with attesta approval.
 *
 * Supports three calling styles:
 * ```ts
 * // Wrap with defaults
 * const safeFn = gate(myFunction);
 *
 * // Wrap with options
 * const safeFn = gate({ risk: "high" })(myFunction);
 *
 * // Wrap with options and function at once
 * const safeFn = gate({ risk: "high" }, myFunction);
 * ```
 *
 * Can also be used as a TypeScript method decorator:
 * ```ts
 * class Agent {
 *   @gateDecorator({ risk: "high" })
 *   async deleteUser(id: string) { ... }
 * }
 * ```
 */
export function gate<TArgs extends unknown[], TReturn>(
  fnOrOptions:
    | ((...args: TArgs) => TReturn | Promise<TReturn>)
    | AttestaDecoratorOptions,
  maybeFn?: (...args: TArgs) => TReturn | Promise<TReturn>
):
  | ((...args: TArgs) => Promise<TReturn>)
  | (<A extends unknown[], R>(
      fn: (...args: A) => R | Promise<R>
    ) => (...args: A) => Promise<R>) {
  // Case 1: gate(fn) -- bare function wrapper
  if (typeof fnOrOptions === "function") {
    return wrapFunction(fnOrOptions, {});
  }

  const options = fnOrOptions;

  // Case 2: gate(options, fn) -- options + function
  if (maybeFn != null) {
    return wrapFunction(maybeFn, options);
  }

  // Case 3: gate(options) -- returns a decorator/wrapper
  return <A extends unknown[], R>(
    fn: (...args: A) => R | Promise<R>
  ): ((...args: A) => Promise<R>) => {
    return wrapFunction(fn, options);
  };
}

/**
 * Method decorator factory for use with TypeScript decorators.
 *
 * Usage:
 * ```ts
 * class Agent {
 *   @gateDecorator({ risk: "high" })
 *   async deleteUser(id: string) { ... }
 * }
 * ```
 */
export function gateDecorator(
  options: AttestaDecoratorOptions = {}
): (
  target: unknown,
  propertyKey: string,
  descriptor: PropertyDescriptor
) => PropertyDescriptor {
  return function (
    _target: unknown,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ): PropertyDescriptor {
    const originalMethod = descriptor.value;
    if (typeof originalMethod !== "function") {
      throw new TypeError(
        `@gateDecorator can only be applied to methods, got ${typeof originalMethod}`
      );
    }

    const attestaInstance = new Attesta({
      riskScorer: options.riskScorer,
      renderer: options.renderer,
      auditLogger: options.auditLogger,
      challengeMap: options.challengeMap,
      minReviewSeconds: options.minReviewSeconds,
      riskOverride: options.risk,
      riskHints: options.riskHints,
    });

    const wrapped = async function (
      this: unknown,
      ...args: unknown[]
    ): Promise<unknown> {
      const ctx = createActionContext({
        functionName: propertyKey || originalMethod.name || "anonymous",
        args,
        kwargs: {},
        hints: { ...(options.riskHints ?? {}) },
        agentId: options.agentId,
        sessionId: options.sessionId,
        environment: options.environment ?? "development",
        metadata: { ...(options.metadata ?? {}) },
      });

      const result = await attestaInstance.evaluate(ctx);
      throwIfDenied(result, describeAction(ctx));

      return originalMethod.apply(this, args);
    };

    Object.defineProperty(wrapped, GATE_SYMBOL, { value: attestaInstance });
    descriptor.value = wrapped;
    return descriptor;
  };
}

// -- internal helpers -------------------------------------------------------

function wrapFunction<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options: AttestaDecoratorOptions
): (...args: TArgs) => Promise<TReturn> {
  const attestaInstance = new Attesta({
    riskScorer: options.riskScorer,
    renderer: options.renderer,
    auditLogger: options.auditLogger,
    challengeMap: options.challengeMap,
    minReviewSeconds: options.minReviewSeconds,
    riskOverride: options.risk,
    riskHints: options.riskHints,
  });

  const wrapper = async function (
    this: unknown,
    ...args: TArgs
  ): Promise<TReturn> {
    const ctx = buildContext(
      fn as (...args: unknown[]) => unknown,
      args,
      options
    );
    const result = await attestaInstance.evaluate(ctx);
    throwIfDenied(result, describeAction(ctx));

    const returnValue = fn.apply(this, args);
    // Support both sync and async wrapped functions.
    return returnValue instanceof Promise ? await returnValue : returnValue;
  };

  // Preserve function name and length.
  Object.defineProperty(wrapper, "name", {
    value: fn.name,
    configurable: true,
  });
  Object.defineProperty(wrapper, "length", {
    value: fn.length,
    configurable: true,
  });

  // Stash the Attesta instance for introspection.
  Object.defineProperty(wrapper, GATE_SYMBOL, { value: attestaInstance });

  return wrapper;
}
