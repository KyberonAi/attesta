/**
 * Risk scoring engine for attesta.
 *
 * This module provides concrete RiskScorer implementations that analyze
 * an ActionContext and produce a continuous risk score in [0.0, 1.0].
 *
 * Scorers can be used individually or composed together:
 * ```ts
 * const scorer = new CompositeRiskScorer([
 *   { scorer: new DefaultRiskScorer(), weight: 0.7 },
 *   { scorer: new FixedRiskScorer(0.5), weight: 0.3 },
 * ]);
 * const assessment = scorer.assess(ctx);
 * ```
 */

import {
  type ActionContext,
  type RiskAssessment,
  type RiskFactor,
  type RiskScorer,
  createRiskAssessment,
  riskLevelFromScore,
} from "./types.js";

// ---------------------------------------------------------------------------
// Pattern constants
// ---------------------------------------------------------------------------

const DESTRUCTIVE_VERBS = new Set([
  "delete",
  "remove",
  "drop",
  "destroy",
  "purge",
  "truncate",
  "kill",
]);

const MUTATING_VERBS = new Set([
  "write",
  "update",
  "modify",
  "set",
  "create",
  "send",
  "deploy",
  "push",
  "execute",
  "run",
]);

const READ_VERBS = new Set([
  "read",
  "get",
  "list",
  "fetch",
  "search",
  "find",
  "check",
]);

const SENSITIVE_PATTERNS = [
  /prod(uction)?/i,
  /\.env\b/i,
  /secret/i,
  /password/i,
  /token/i,
  /\bkey\b/i,
  /credential/i,
] as const;

const SQL_DANGER = [
  /\bDROP\b/i,
  /\bDELETE\b/i,
  /\bTRUNCATE\b/i,
  /\bALTER\b/i,
] as const;

const SHELL_DANGER = [
  /rm\s+-rf\b/,
  /\bsudo\b/,
  /chmod\s+777\b/,
] as const;

const NETWORK_PATTERNS = [
  /https?:\/\//i,
  /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/,
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
] as const;

const DOCSTRING_HIGH = [
  /irreversible/i,
  /permanent/i,
  /destructive/i,
  /dangerous/i,
  /production/i,
  /critical/i,
] as const;

const DOCSTRING_MEDIUM = [
  /careful/i,
  /warning/i,
  /caution/i,
] as const;

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

function clamp(value: number, lo: number = 0.0, hi: number = 1.0): number {
  return Math.max(lo, Math.min(hi, value));
}

function flattenArgs(
  args: readonly unknown[],
  kwargs: Record<string, unknown>
): string[] {
  const parts: string[] = [];
  for (const a of args) {
    parts.push(String(a));
  }
  for (const v of Object.values(kwargs)) {
    parts.push(String(v));
  }
  return parts;
}

function extractVerbs(functionName: string): string[] {
  // Replace camelCase boundaries with underscores first, then split.
  const snake = functionName.replace(/(?<=[a-z0-9])(?=[A-Z])/g, "_");
  return snake
    .split(/[_.\-/]+/)
    .filter(Boolean)
    .map((tok) => tok.toLowerCase());
}

// ---------------------------------------------------------------------------
// Score result type
// ---------------------------------------------------------------------------

interface ScoreResult {
  score: number;
  evidence: string;
}

// ---------------------------------------------------------------------------
// DefaultRiskScorer
// ---------------------------------------------------------------------------

/**
 * Options for configuring the DefaultRiskScorer.
 */
export interface DefaultRiskScorerOptions {
  /** Weight for the function name factor (default 0.30). */
  weightFunction?: number;

  /** Weight for the arguments factor (default 0.25). */
  weightArgs?: number;

  /** Weight for the docstring factor (default 0.20). */
  weightDocstring?: number;

  /** Weight for the hints factor (default 0.15). */
  weightHints?: number;

  /** Weight for the novelty factor (default 0.10). */
  weightNovelty?: number;
}

/**
 * Built-in heuristic risk scorer.
 *
 * Analyzes five independent factors of an ActionContext and produces
 * a weighted composite score:
 *
 * | Factor        | Weight | Signal                                  |
 * |---------------|--------|-----------------------------------------|
 * | functionName  | 0.30   | Destructive / mutating / read verbs     |
 * | arguments     | 0.25   | Sensitive values, SQL, shell commands    |
 * | docstring     | 0.20   | Danger / caution keywords               |
 * | hints         | 0.15   | Caller-supplied risk metadata            |
 * | novelty       | 0.10   | How often this function has been scored  |
 *
 * The scorer is stateful: it maintains a call counter for the novelty
 * factor. Instances are not thread-safe.
 */
export class DefaultRiskScorer implements RiskScorer {
  readonly weightFunction: number;
  readonly weightArgs: number;
  readonly weightDocstring: number;
  readonly weightHints: number;
  readonly weightNovelty: number;

  private _callCounts = new Map<string, number>();

  constructor(options: DefaultRiskScorerOptions = {}) {
    this.weightFunction = options.weightFunction ?? 0.3;
    this.weightArgs = options.weightArgs ?? 0.25;
    this.weightDocstring = options.weightDocstring ?? 0.2;
    this.weightHints = options.weightHints ?? 0.15;
    this.weightNovelty = options.weightNovelty ?? 0.1;
  }

  get name(): string {
    return "default";
  }

  /**
   * Return a risk score in [0.0, 1.0] for the given action context.
   */
  score(ctx: ActionContext): number {
    const factors = this._computeFactors(ctx);
    let finalScore = factors.reduce((sum, f) => sum + f.contribution, 0);
    finalScore = clamp(finalScore);

    // Environment risk multiplier
    const envMultipliers: Record<string, number> = {
      production: 1.3,
      staging: 1.1,
      development: 0.8,
      testing: 0.7,
      local: 0.6,
    };
    const envMultiplier = envMultipliers[ctx.environment ?? ""] ?? 1.0;
    if (envMultiplier !== 1.0) {
      finalScore = Math.min(1.0, Math.max(0.0, finalScore * envMultiplier));
    }

    return finalScore;
  }

  /**
   * Produce a full RiskAssessment with factor breakdown.
   */
  assess(ctx: ActionContext): RiskAssessment {
    const factors = this._computeFactors(ctx);
    let finalScore = factors.reduce((sum, f) => sum + f.contribution, 0);
    finalScore = clamp(finalScore);

    // Environment risk multiplier
    const envMultipliers: Record<string, number> = {
      production: 1.3,
      staging: 1.1,
      development: 0.8,
      testing: 0.7,
      local: 0.6,
    };
    const envMultiplier = envMultipliers[ctx.environment ?? ""] ?? 1.0;
    if (envMultiplier !== 1.0) {
      const envAdjusted = Math.min(
        1.0,
        Math.max(0.0, finalScore * envMultiplier)
      );
      factors.push({
        name: "environment_multiplier",
        contribution: envAdjusted - finalScore,
        description: `Environment '${ctx.environment}' multiplier ${envMultiplier}x adjusted risk from ${finalScore.toFixed(2)} to ${envAdjusted.toFixed(2)}`,
      });
      finalScore = envAdjusted;
    }

    return createRiskAssessment({
      score: finalScore,
      level: riskLevelFromScore(finalScore),
      factors,
      scorerName: this.name,
    });
  }

  /**
   * Clear the internal call counter (useful in tests).
   */
  resetNovelty(): void {
    this._callCounts.clear();
  }

  // -- Factor computation ------------------------------------------------

  private _computeFactors(ctx: ActionContext): RiskFactor[] {
    const factors: RiskFactor[] = [];

    const fn = DefaultRiskScorer._scoreFunctionName(ctx.functionName);
    factors.push({
      name: "function_name",
      contribution: fn.score * this.weightFunction,
      description: "Risk inferred from the function name verbs.",
      evidence: fn.evidence,
    });

    const arg = DefaultRiskScorer._scoreArguments(ctx.args, ctx.kwargs);
    factors.push({
      name: "arguments",
      contribution: arg.score * this.weightArgs,
      description: "Risk inferred from argument values.",
      evidence: arg.evidence,
    });

    const doc = DefaultRiskScorer._scoreDocstring(ctx.functionDoc);
    factors.push({
      name: "docstring",
      contribution: doc.score * this.weightDocstring,
      description: "Risk inferred from the function docstring.",
      evidence: doc.evidence,
    });

    const hint = DefaultRiskScorer._scoreHints(ctx.hints);
    factors.push({
      name: "hints",
      contribution: hint.score * this.weightHints,
      description: "Risk inferred from caller-supplied hints.",
      evidence: hint.evidence,
    });

    const nov = this._scoreNovelty(ctx.functionName);
    factors.push({
      name: "novelty",
      contribution: nov.score * this.weightNovelty,
      description: "Risk due to function call novelty.",
      evidence: nov.evidence,
    });

    return factors;
  }

  // -- Individual factor scorers -----------------------------------------

  private static _scoreFunctionName(functionName: string): ScoreResult {
    const tokens = extractVerbs(functionName);
    if (tokens.length === 0) {
      return { score: 0.5, evidence: "no recognisable tokens" };
    }

    const destructive = tokens.filter((t) => DESTRUCTIVE_VERBS.has(t));
    const mutating = tokens.filter((t) => MUTATING_VERBS.has(t));
    const reading = tokens.filter((t) => READ_VERBS.has(t));

    if (destructive.length > 0) {
      return {
        score: 0.95,
        evidence: `destructive verbs: ${destructive.join(", ")}`,
      };
    }
    if (mutating.length > 0) {
      return {
        score: 0.55,
        evidence: `mutating verbs: ${mutating.join(", ")}`,
      };
    }
    if (reading.length > 0) {
      return {
        score: 0.1,
        evidence: `read verbs: ${reading.join(", ")}`,
      };
    }

    return { score: 0.4, evidence: "no known verb category matched" };
  }

  private static _scoreArguments(
    args: readonly unknown[],
    kwargs: Record<string, unknown>
  ): ScoreResult {
    const flat = flattenArgs(args, kwargs);
    if (flat.length === 0) {
      return { score: 0.0, evidence: "no arguments" };
    }

    const combined = flat.join(" ");
    const evidenceParts: string[] = [];
    let maxScore = 0.0;

    // High-risk: sensitive values.
    for (const pat of SENSITIVE_PATTERNS) {
      const match = pat.exec(combined);
      if (match) {
        evidenceParts.push(`sensitive pattern '${match[0]}'`);
        maxScore = Math.max(maxScore, 0.9);
      }
    }

    // High-risk: dangerous SQL.
    for (const pat of SQL_DANGER) {
      const match = pat.exec(combined);
      if (match) {
        evidenceParts.push(`SQL keyword '${match[0]}'`);
        maxScore = Math.max(maxScore, 0.9);
      }
    }

    // High-risk: dangerous shell commands.
    for (const pat of SHELL_DANGER) {
      const match = pat.exec(combined);
      if (match) {
        evidenceParts.push(`shell command '${match[0]}'`);
        maxScore = Math.max(maxScore, 0.9);
      }
    }

    // Medium-risk: URLs, emails, IPs.
    for (const pat of NETWORK_PATTERNS) {
      const match = pat.exec(combined);
      if (match) {
        evidenceParts.push(`network pattern '${match[0]}'`);
        maxScore = Math.max(maxScore, 0.5);
      }
    }

    if (evidenceParts.length > 0) {
      return { score: maxScore, evidence: evidenceParts.join("; ") };
    }
    return { score: 0.05, evidence: "arguments appear benign" };
  }

  private static _scoreDocstring(doc: string | undefined): ScoreResult {
    if (!doc) {
      return { score: 0.1, evidence: "no docstring available" };
    }

    const evidenceParts: string[] = [];
    let maxScore = 0.0;

    for (const pat of DOCSTRING_HIGH) {
      const match = pat.exec(doc);
      if (match) {
        evidenceParts.push(`high-risk keyword '${match[0]}'`);
        maxScore = Math.max(maxScore, 0.85);
      }
    }

    for (const pat of DOCSTRING_MEDIUM) {
      const match = pat.exec(doc);
      if (match) {
        evidenceParts.push(`caution keyword '${match[0]}'`);
        maxScore = Math.max(maxScore, 0.5);
      }
    }

    if (evidenceParts.length > 0) {
      return { score: maxScore, evidence: evidenceParts.join("; ") };
    }
    return { score: 0.05, evidence: "docstring contains no risk keywords" };
  }

  private static _scoreHints(
    hints: Record<string, unknown>
  ): ScoreResult {
    const keys = Object.keys(hints);
    if (keys.length === 0) {
      return { score: 0.0, evidence: "no hints provided" };
    }

    let total = 0.0;
    const evidenceParts: string[] = [];

    for (const [key, value] of Object.entries(hints)) {
      if (typeof value === "boolean") {
        if (value) {
          total += 0.3;
          evidenceParts.push(`${key}=true (+0.30)`);
        }
      } else if (typeof value === "number") {
        const contribution = Math.min(value / 10_000, 1.0) * 0.8;
        total += contribution;
        evidenceParts.push(`${key}=${value} (+${contribution.toFixed(2)})`);
      }
    }

    const clamped = clamp(total);
    if (evidenceParts.length > 0) {
      return { score: clamped, evidence: evidenceParts.join("; ") };
    }
    return { score: 0.0, evidence: "hints contained no scorable values" };
  }

  private _scoreNovelty(functionName: string): ScoreResult {
    const count = this._callCounts.get(functionName) ?? 0;
    this._callCounts.set(functionName, count + 1);

    let score: number;
    if (count === 0) {
      score = 0.9;
    } else if (count >= 10) {
      score = 0.1;
    } else {
      // Linear interpolation: count 1 -> 0.81, count 9 -> 0.18 ...
      score = 0.9 - (count / 10) * 0.8;
    }

    return { score, evidence: `seen ${count} time(s) before` };
  }
}

// ---------------------------------------------------------------------------
// CompositeRiskScorer
// ---------------------------------------------------------------------------

/**
 * A scorer-weight pair for use with CompositeRiskScorer.
 */
export interface ScorerWeight {
  /** The risk scorer instance. */
  scorer: RiskScorer;

  /** The weight assigned to this scorer (positive number). */
  weight: number;
}

/**
 * Combines multiple scorers via a weighted average.
 *
 * ```ts
 * const scorer = new CompositeRiskScorer([
 *   { scorer: new DefaultRiskScorer(), weight: 0.7 },
 *   { scorer: myCustomScorer, weight: 0.3 },
 * ]);
 * ```
 *
 * Weights do not need to sum to 1.0 -- they are normalised internally.
 */
export class CompositeRiskScorer implements RiskScorer {
  readonly scorers: readonly ScorerWeight[];

  constructor(scorers: ScorerWeight[]) {
    if (scorers.length === 0) {
      throw new Error("CompositeRiskScorer requires at least one scorer");
    }
    const totalWeight = scorers.reduce((sum, s) => sum + s.weight, 0);
    if (totalWeight <= 0) {
      throw new Error("Total weight must be positive");
    }
    this.scorers = scorers;
  }

  get name(): string {
    const names = this.scorers.map((s) => s.scorer.name).join("+");
    return `composite(${names})`;
  }

  score(ctx: ActionContext): number {
    const totalWeight = this.scorers.reduce((sum, s) => sum + s.weight, 0);
    const weightedSum = this.scorers.reduce(
      (sum, s) => sum + s.scorer.score(ctx) * s.weight,
      0
    );
    return clamp(weightedSum / totalWeight);
  }

  assess(ctx: ActionContext): RiskAssessment {
    const totalWeight = this.scorers.reduce((sum, s) => sum + s.weight, 0);
    const factors: RiskFactor[] = [];
    let weightedSum = 0;

    for (const { scorer, weight } of this.scorers) {
      const childScore = scorer.score(ctx);
      const normalisedWeight = weight / totalWeight;
      const contribution = childScore * normalisedWeight;
      weightedSum += contribution;
      factors.push({
        name: `scorer:${scorer.name}`,
        contribution,
        description:
          `Score ${childScore.toFixed(3)} from '${scorer.name}' ` +
          `(weight ${normalisedWeight.toFixed(2)})`,
      });
    }

    const clamped = clamp(weightedSum);
    return createRiskAssessment({
      score: clamped,
      level: riskLevelFromScore(clamped),
      factors,
      scorerName: this.name,
    });
  }
}

// ---------------------------------------------------------------------------
// MaxRiskScorer
// ---------------------------------------------------------------------------

/**
 * Takes the maximum score from multiple scorers (most conservative).
 *
 * ```ts
 * const scorer = new MaxRiskScorer([new DefaultRiskScorer(), myCustomScorer]);
 * ```
 *
 * This is useful when you want to guarantee that the highest individual risk
 * signal is never diluted by averaging.
 */
export class MaxRiskScorer implements RiskScorer {
  readonly scorers: readonly RiskScorer[];

  constructor(scorers: RiskScorer[]) {
    if (scorers.length === 0) {
      throw new Error("MaxRiskScorer requires at least one scorer");
    }
    this.scorers = scorers;
  }

  get name(): string {
    const names = this.scorers.map((s) => s.name).join(",");
    return `max(${names})`;
  }

  score(ctx: ActionContext): number {
    return clamp(Math.max(...this.scorers.map((s) => s.score(ctx))));
  }

  assess(ctx: ActionContext): RiskAssessment {
    let bestScore = 0;
    let bestScorerName = "";
    const factors: RiskFactor[] = [];

    for (const scorer of this.scorers) {
      const childScore = scorer.score(ctx);
      if (childScore >= bestScore) {
        bestScore = childScore;
        bestScorerName = scorer.name;
      }
      factors.push({
        name: `scorer:${scorer.name}`,
        contribution: childScore,
        description: `Score ${childScore.toFixed(3)} from '${scorer.name}'`,
      });
    }

    const clamped = clamp(bestScore);
    return createRiskAssessment({
      score: clamped,
      level: riskLevelFromScore(clamped),
      factors,
      scorerName: `max(winner=${bestScorerName})`,
    });
  }
}

// ---------------------------------------------------------------------------
// FixedRiskScorer
// ---------------------------------------------------------------------------

/**
 * Always returns a fixed, pre-configured risk score.
 *
 * Useful for testing, explicit overrides, or as a floor/ceiling in a
 * CompositeRiskScorer.
 *
 * ```ts
 * const scorer = new FixedRiskScorer(0.9); // always critical
 * ```
 */
export class FixedRiskScorer implements RiskScorer {
  readonly fixedScore: number;

  constructor(fixedScore: number = 0.5) {
    if (fixedScore < 0.0 || fixedScore > 1.0) {
      throw new RangeError(
        `fixedScore must be in [0.0, 1.0], got ${fixedScore}`
      );
    }
    this.fixedScore = fixedScore;
  }

  get name(): string {
    return `fixed(${this.fixedScore.toFixed(2)})`;
  }

  score(_ctx: ActionContext): number {
    return this.fixedScore;
  }

  assess(_ctx: ActionContext): RiskAssessment {
    return createRiskAssessment({
      score: this.fixedScore,
      level: riskLevelFromScore(this.fixedScore),
      factors: [
        {
          name: "fixed",
          contribution: this.fixedScore,
          description: `Hardcoded risk score of ${this.fixedScore.toFixed(2)}.`,
        },
      ],
      scorerName: this.name,
    });
  }
}
