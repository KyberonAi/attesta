/**
 * Teach-back challenge for CRITICAL-risk actions.
 *
 * The operator must explain, in their own words, what the action will do
 * and what its effects are. This is the strongest single-person challenge
 * because it requires active comprehension rather than passive recognition.
 */

import * as pathModule from "node:path";

import {
  type ActionContext,
  type ChallengeProtocol,
  type ChallengeResult,
  ChallengeType,
  type RiskAssessment,
  createChallengeResult,
  describeAction,
} from "../types.js";

import {
  type TeachBackValidator,
  KeywordValidator,
} from "./validators.js";

// ---------------------------------------------------------------------------
// Key term extraction
// ---------------------------------------------------------------------------

/**
 * Derive a set of key terms from the action context.
 *
 * Key terms are the building blocks used to check whether the operator's
 * free-text explanation demonstrates genuine comprehension. They come from:
 *
 * - Parts of the function name (split on `_`, `-`, and camelCase boundaries).
 * - Significant keyword-argument values (strings longer than 2 chars,
 *   path basenames, table names, etc.).
 * - Significant positional-argument values using the same heuristics.
 */
function extractKeyTerms(ctx: ActionContext): string[] {
  const terms: string[] = [];

  // Function name parts
  const nameParts = ctx.functionName
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/-/g, " ")
    .replace(/_/g, " ");
  for (const word of nameParts.split(/\s+/)) {
    const cleaned = word.trim().toLowerCase();
    if (cleaned.length > 2) {
      terms.push(cleaned);
    }
  }

  // Significant argument values
  const allValues: unknown[] = [
    ...ctx.args,
    ...Object.values(ctx.kwargs),
  ];
  for (const val of allValues) {
    if (typeof val === "string" && val.length > 2) {
      // Try to extract the basename of a path
      if (val.includes("/") || val.includes("\\")) {
        terms.push(pathModule.basename(val).toLowerCase());
      }
      // Short-ish strings are likely identifiers or names
      if (val.length <= 80) {
        terms.push(val.trim().toLowerCase());
      }
    } else if (typeof val === "number") {
      terms.push(String(val));
    }
  }

  // Deduplicate while preserving order
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const t of terms) {
    if (!seen.has(t)) {
      seen.add(t);
      unique.push(t);
    }
  }
  return unique;
}

// ---------------------------------------------------------------------------
// TeachBackChallenge options
// ---------------------------------------------------------------------------

/**
 * Options for configuring the TeachBackChallenge.
 */
export interface TeachBackChallengeOptions {
  /** Minimum word count for the operator's explanation. Default 15. */
  minWords?: number;

  /**
   * Wall-clock seconds the action summary must be visible before the
   * prompt becomes active. Default 30.
   */
  minReviewSeconds?: number;

  /**
   * Pluggable validator for teach-back explanations. When provided, replaces
   * the default keyword-based validation. See `KeywordValidator` or implement
   * the `TeachBackValidator` interface.
   */
  validator?: TeachBackValidator;

  /** Custom input function. */
  promptFn?: (prompt: string) => Promise<string>;

  /** Custom output function. */
  printFn?: (message: string) => void;
}

// ---------------------------------------------------------------------------
// TeachBackChallenge
// ---------------------------------------------------------------------------

/**
 * Teach-back verification for CRITICAL-risk actions.
 *
 * The operator is shown the full action details and asked to explain, in
 * their own words, what the action will do and what its effects are.
 *
 * Validation rules:
 *
 * 1. The response must be at least `minWords` words long.
 * 2. The response must contain at least one key term extracted from
 *    the action context (function name parts, significant arg values).
 * 3. (Optional) A custom validator can apply additional checks.
 */
export class TeachBackChallenge implements ChallengeProtocol {
  readonly minWords: number;
  readonly minReviewSeconds: number;
  private readonly _validator: TeachBackValidator;
  private readonly _promptFn: (prompt: string) => Promise<string>;
  private readonly _printFn: (message: string) => void;

  constructor(options: TeachBackChallengeOptions = {}) {
    this.minWords = options.minWords ?? 15;
    this.minReviewSeconds = options.minReviewSeconds ?? 30.0;
    this._promptFn = options.promptFn ?? defaultPrompt;
    this._printFn = options.printFn ?? defaultPrint;

    this._validator = options.validator ?? new KeywordValidator({ minWords: this.minWords });
  }

  get challengeType(): ChallengeType {
    return ChallengeType.TEACH_BACK;
  }

  // -- presentation -------------------------------------------------------

  /**
   * Present the teach-back challenge to the operator.
   */
  async present(
    ctx: ActionContext,
    risk: RiskAssessment
  ): Promise<ChallengeResult> {
    const start = performance.now();
    const print = this._printFn;
    const prompt = this._promptFn;

    // -- render full action details -------------------------------------
    const separator = "=".repeat(60);
    print(`\n${separator}`);
    print("  TEACH-BACK CHALLENGE  --  CRITICAL RISK ACTION");
    print(separator);
    print(`  Action:      ${ctx.functionName}`);
    print(
      `  Risk:        ${risk.level.toUpperCase()} (${risk.score.toFixed(2)})`
    );
    if (ctx.functionDoc) {
      print(`  Description: ${ctx.functionDoc}`);
    }
    print(`  Call:        ${describeAction(ctx)}`);
    if (ctx.args.length > 0) {
      print(`  Positional:  ${JSON.stringify(ctx.args)}`);
    }
    if (Object.keys(ctx.kwargs).length > 0) {
      print(`  Keyword:     ${JSON.stringify(ctx.kwargs)}`);
    }
    if (risk.factors.length > 0) {
      print("  Risk factors:");
      for (const factor of risk.factors) {
        print(`    - ${factor.name}: ${factor.description}`);
      }
    }
    print(separator);

    // -- enforce minimum review time ------------------------------------
    const elapsed = (performance.now() - start) / 1000;
    if (elapsed < this.minReviewSeconds) {
      const remaining = this.minReviewSeconds - elapsed;
      print(
        `  [Read carefully. Prompt activates in ${Math.round(remaining)}s...]`
      );
      await sleep(remaining);
    }

    // -- collect free-text explanation -----------------------------------
    print(
      "\n  In your own words, explain what this action will do and " +
        "what its effects are:"
    );
    const explanation = (await prompt("  > ")).trim();

    // -- validate via pluggable validator ---------------------------------
    const validatorResult = await this._validator.validate(explanation, ctx);
    const passed = validatorResult.passed;
    const validationNotes: string[] = [validatorResult.notes];

    // Extract details for backward-compatible result structure
    const keyTerms = extractKeyTerms(ctx);
    const explanationLower = explanation.toLowerCase();
    const matchedTerms = keyTerms.filter((t) =>
      explanationLower.includes(t)
    );
    const wordCount = explanation.split(/\s+/).filter(Boolean).length;
    const totalElapsed = (performance.now() - start) / 1000;

    const status = passed ? "PASSED" : "FAILED";
    print(`\n  Teach-back result: ${status}`);
    for (const note of validationNotes) {
      print(`    - ${note}`);
    }

    return createChallengeResult({
      passed,
      challengeType: this.challengeType,
      responseTimeSeconds: totalElapsed,
      questionsAsked: 1,
      questionsCorrect: passed ? 1 : 0,
      details: {
        explanation,
        wordCount,
        keyTerms,
        matchedTerms,
        passed,
        validationNotes,
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Default I/O helpers
// ---------------------------------------------------------------------------

function defaultPrint(message: string): void {
  // eslint-disable-next-line no-console
  console.log(message);
}

async function defaultPrompt(message: string): Promise<string> {
  const { createInterface } = await import("node:readline");
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<string>((resolve) => {
    rl.question(message, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function sleep(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}
