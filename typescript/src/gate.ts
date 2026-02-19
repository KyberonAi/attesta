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

import { DefaultRiskScorer } from "./risk.js";
import { TrustEngine } from "./trust.js";

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

export type FailMode = "deny" | "allow" | "escalate";

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

  /** Optional trust engine for adaptive risk adjustment. */
  trustEngine?: TrustEngine;

  /** How much trust influences risk scoring (0-1). Default 0.3. */
  trustInfluence?: number;

  /** Timeout policy: deny (default), allow, or escalate. */
  failMode?: FailMode;

  /** Maximum seconds to wait for challenge completion before timeout policy. */
  approvalTimeoutSeconds?: number;
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
  private _renderer?: Renderer;
  private _rendererResolved: boolean;
  private readonly _audit: AuditLoggerProtocol;
  private readonly _challengeMap?: Partial<Record<RiskLevel, ChallengeType>>;
  private readonly _minReviewSeconds: number;
  private readonly _riskOverride?: RiskLevel;
  private readonly _riskHints: Record<string, unknown>;
  private readonly _eventBus?: import("./events.js").EventBus;
  private readonly _trustEngine?: TrustEngine;
  private readonly _trustInfluence: number;
  private readonly _failMode: FailMode;
  private readonly _approvalTimeoutSeconds: number;

  constructor(options: AttestaOptions = {}) {
    this._scorer = options.riskScorer ?? new DefaultRiskScorer();
    this._renderer = options.renderer;
    this._rendererResolved = options.renderer != null;
    this._audit = options.auditLogger ?? new DefaultAuditLogger();
    this._challengeMap = options.challengeMap;
    this._minReviewSeconds = options.minReviewSeconds ?? 0;
    this._riskOverride = options.riskOverride;
    this._riskHints = options.riskHints ?? {};
    this._eventBus = options.eventBus;
    this._trustEngine = options.trustEngine;
    this._trustInfluence = options.trustInfluence ?? 0.3;
    this._failMode = options.failMode ?? "deny";
    this._approvalTimeoutSeconds = options.approvalTimeoutSeconds ?? 600;

    if (!["deny", "allow", "escalate"].includes(this._failMode)) {
      throw new TypeError(
        `Invalid failMode '${this._failMode}'. Expected one of: deny, allow, escalate.`
      );
    }
    if (this._approvalTimeoutSeconds <= 0) {
      throw new RangeError(
        `approvalTimeoutSeconds must be > 0, got ${this._approvalTimeoutSeconds}`
      );
    }
  }

  /**
   * Lazily resolve the renderer on first use.
   * If no renderer was provided, detect TTY and choose appropriately.
   */
  private async _resolveRenderer(): Promise<Renderer> {
    if (this._rendererResolved && this._renderer) {
      return this._renderer;
    }

    if (!this._rendererResolved) {
      this._rendererResolved = true;

      // If no renderer specified, detect environment
      if (
        typeof process !== "undefined" &&
        process.stdout?.isTTY
      ) {
        try {
          const { TerminalRenderer } = await import(
            "./renderers/terminal.js"
          );
          this._renderer = new TerminalRenderer();
        } catch {
          // Fall through to deny-all
        }
      }

      if (!this._renderer) {
        // Non-interactive: deny by default for safety
        this._renderer = {
          async renderApproval() {
            return Verdict.DENIED;
          },
          async renderChallenge(
            _ctx: ActionContext,
            _risk: RiskAssessment,
            challengeType: ChallengeType
          ) {
            return createChallengeResult({
              passed: false,
              challengeType,
              questionsAsked: 0,
              questionsCorrect: 0,
              details: { reason: "No interactive terminal available" },
            });
          },
          async renderInfo() {},
          async renderAutoApproved() {},
        };
        // eslint-disable-next-line no-console
        console.warn(
          "[attesta] No TTY detected. Using deny-all renderer. Configure a renderer explicitly for non-interactive environments."
        );
      }
    }

    return this._renderer!;
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

  private _timeoutOutcome(challengeType: ChallengeType): {
    verdict: Verdict;
    challengeResult: ChallengeResult;
    metadata: Record<string, unknown>;
  } {
    const timeoutReason =
      `Approval timed out after ${this._approvalTimeoutSeconds.toFixed(0)}s`;

    const challengeResult = createChallengeResult({
      passed: false,
      challengeType,
      details: {
        reason: timeoutReason,
        failMode: this._failMode,
        timeoutSeconds: this._approvalTimeoutSeconds,
      },
    });

    let verdict: Verdict;
    if (this._failMode === "allow") {
      verdict = Verdict.APPROVED;
    } else if (this._failMode === "escalate") {
      verdict = Verdict.ESCALATED;
    } else {
      verdict = Verdict.TIMED_OUT;
    }

    return {
      verdict,
      challengeResult,
      metadata: {
        failMode: this._failMode,
        approvalTimeoutSeconds: this._approvalTimeoutSeconds,
        timedOut: true,
        timeoutReason,
      },
    };
  }

  /**
   * Run the full approval pipeline and return the result.
   */
  async evaluate(ctx: ActionContext): Promise<ApprovalResult> {
    const renderer = await this._resolveRenderer();
    const reviewStart = performance.now();

    // 1. Merge extra hints.
    if (Object.keys(this._riskHints).length > 0) {
      ctx.hints = { ...ctx.hints, ...this._riskHints };
    }

    // 2. Risk scoring.
    let risk = this._assessRisk(ctx);

    await this._emit("risk_scored", {
      actionName: ctx.functionName,
      riskScore: risk.score,
      riskLevel: risk.level,
    });

    // Trust-based risk adjustment
    let adjustedScore = risk.score;
    const originalLevel = risk.level;
    if (this._trustEngine && ctx.agentId) {
      const domain =
        (ctx.hints?.domain as string) ?? ctx.environment ?? "general";
      const trustScore = this._trustEngine.computeTrust(ctx.agentId, domain);
      adjustedScore =
        adjustedScore * (1 - trustScore * this._trustInfluence);
      adjustedScore = Math.max(0, Math.min(1, adjustedScore));

      // Safety invariant: CRITICAL actions never downgraded
      if (originalLevel !== "critical") {
        const adjustedLevel = riskLevelFromScore(adjustedScore);
        risk = {
          ...risk,
          score: adjustedScore,
          level: adjustedLevel,
          factors: [
            ...risk.factors,
            {
              name: "trust_adjustment",
              contribution: adjustedScore - risk.score,
              description: `Trust engine adjusted risk from ${risk.score.toFixed(2)} to ${adjustedScore.toFixed(2)}`,
            },
          ],
        };
      }
    }

    // 3. Select challenge.
    const challengeType = selectChallenge(risk, this._challengeMap);

    // 4. Present challenge / collect verdict.
    let challengeResult: ChallengeResult | undefined;
    let verdict: Verdict;
    const resultMetadata: Record<string, unknown> = {
      failMode: this._failMode,
      approvalTimeoutSeconds: this._approvalTimeoutSeconds,
    };

    if (challengeType === ChallengeType.AUTO_APPROVE) {
      verdict = Verdict.APPROVED;
      await renderer.renderAutoApproved(ctx, risk);
    } else {
      await this._emit("challenge_issued", {
        actionName: ctx.functionName,
        challengeType,
        riskLevel: risk.level,
      });
      const timeoutMs = this._approvalTimeoutSeconds * 1000;
      class _ApprovalTimeoutError extends Error {}
      let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
      try {
        challengeResult = await Promise.race([
          renderer.renderChallenge(ctx, risk, challengeType),
          new Promise<ChallengeResult>((_resolve, reject) => {
            timeoutHandle = setTimeout(() => {
              reject(new _ApprovalTimeoutError("approval timeout"));
            }, timeoutMs);
          }),
        ]);
        verdict = challengeResult.passed ? Verdict.APPROVED : Verdict.DENIED;
      } catch (err) {
        if (!(err instanceof _ApprovalTimeoutError)) {
          throw err;
        }
        const timeoutOutcome = this._timeoutOutcome(challengeType);
        verdict = timeoutOutcome.verdict;
        challengeResult = timeoutOutcome.challengeResult;
        Object.assign(resultMetadata, timeoutOutcome.metadata);
      } finally {
        if (timeoutHandle != null) {
          clearTimeout(timeoutHandle);
        }
      }
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
      metadata: resultMetadata,
    });

    // 6b. Emit verdict event.
    const verdictEvent =
      verdict === Verdict.APPROVED
        ? "approved"
        : verdict === Verdict.ESCALATED
          ? "escalated"
          : "denied";
    await this._emit(verdictEvent, {
      actionName: ctx.functionName,
      riskScore: risk.score,
      riskLevel: risk.level,
      verdict,
    });

    // 6c. Update trust engine
    if (this._trustEngine && ctx.agentId) {
      const domain =
        (ctx.hints?.domain as string) ?? ctx.environment ?? "general";
      if (verdict === Verdict.APPROVED) {
        this._trustEngine.recordSuccess({
          agentId: ctx.agentId,
          actionName: ctx.functionName,
          domain,
          riskScore: risk.score,
        });
      } else {
        this._trustEngine.recordDenial({
          agentId: ctx.agentId,
          actionName: ctx.functionName,
          domain,
          riskScore: risk.score,
        });
      }
    }

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

    const scorerWithAssess = this._scorer as RiskScorer & {
      assess?: (context: ActionContext) => RiskAssessment;
    };
    if (typeof scorerWithAssess.assess === "function") {
      const assessed = scorerWithAssess.assess(ctx);
      const score = Math.max(0.0, Math.min(1.0, assessed.score));
      return createRiskAssessment({
        score,
        level: riskLevelFromScore(score),
        factors: assessed.factors,
        scorerName: assessed.scorerName ?? this._scorer.name,
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
  /** Reuse an existing Attesta instance for this gate wrapper. */
  attesta?: Attesta;

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
 * Use as a function-first wrapper with options: `gate(myFunction, options)`.
 */
export function gate<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options: AttestaDecoratorOptions
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
  maybeFnOrOptions?:
    | ((...args: TArgs) => TReturn | Promise<TReturn>)
    | AttestaDecoratorOptions
):
  | ((...args: TArgs) => Promise<TReturn>)
  | (<A extends unknown[], R>(
      fn: (...args: A) => R | Promise<R>
    ) => (...args: A) => Promise<R>) {
  // Case 1: gate(fn) or gate(fn, options)
  if (typeof fnOrOptions === "function") {
    if (maybeFnOrOptions != null && typeof maybeFnOrOptions === "function") {
      throw new TypeError(
        "Invalid gate() call: second argument must be options when first argument is a function."
      );
    }
    if (maybeFnOrOptions != null) {
      return wrapFunction(fnOrOptions, maybeFnOrOptions);
    }
    return wrapFunction(fnOrOptions, {});
  }

  const options = fnOrOptions;

  // Case 2: gate(options, fn) -- options + function
  if (maybeFnOrOptions != null) {
    if (typeof maybeFnOrOptions !== "function") {
      throw new TypeError(
        "Invalid gate() call: expected a function as the second argument for gate(options, fn)."
      );
    }
    return wrapFunction(maybeFnOrOptions, options);
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
      trustEngine: options.trustEngine,
      trustInfluence: options.trustInfluence,
      failMode: options.failMode,
      approvalTimeoutSeconds: options.approvalTimeoutSeconds,
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
  const attestaInstance =
    options.attesta ??
    new Attesta({
      riskScorer: options.riskScorer,
      renderer: options.renderer,
      auditLogger: options.auditLogger,
      challengeMap: options.challengeMap,
      minReviewSeconds: options.minReviewSeconds,
      riskOverride: options.risk,
      riskHints: options.riskHints,
      trustEngine: options.trustEngine,
      trustInfluence: options.trustInfluence,
      failMode: options.failMode,
      approvalTimeoutSeconds: options.approvalTimeoutSeconds,
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
