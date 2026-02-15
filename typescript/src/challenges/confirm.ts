/**
 * Simple confirmation challenge for MEDIUM-risk actions.
 *
 * Presents a human-readable summary of the pending action and waits for
 * explicit Y/N approval. A configurable minimum review time prevents
 * reflexive "yes" responses by forcing the operator to wait before the
 * prompt becomes active.
 */

import {
  type ActionContext,
  type ChallengeProtocol,
  type ChallengeResult,
  ChallengeType,
  type RiskAssessment,
  createChallengeResult,
  describeAction,
} from "../types.js";

/**
 * Options for configuring the ConfirmChallenge.
 */
export interface ConfirmChallengeOptions {
  /**
   * Minimum wall-clock seconds the summary must be visible before the
   * operator is allowed to approve. Defaults to 3.0.
   */
  minReviewSeconds?: number;

  /**
   * Custom input function for collecting the operator's response.
   * By default, uses Node.js readline (stdin/stdout).
   * Signature: () => Promise<string>
   */
  promptFn?: () => Promise<string>;

  /**
   * Custom output function for displaying information.
   * By default, uses console.log.
   */
  printFn?: (message: string) => void;
}

/**
 * Simple Y/N confirmation with action summary.
 *
 * Suitable for MEDIUM-risk actions where a quick approval is sufficient.
 */
export class ConfirmChallenge implements ChallengeProtocol {
  readonly minReviewSeconds: number;
  private readonly _promptFn: () => Promise<string>;
  private readonly _printFn: (message: string) => void;

  constructor(options: ConfirmChallengeOptions = {}) {
    this.minReviewSeconds = options.minReviewSeconds ?? 3.0;
    this._promptFn = options.promptFn ?? defaultPrompt;
    this._printFn = options.printFn ?? defaultPrint;
  }

  get challengeType(): ChallengeType {
    return ChallengeType.CONFIRM;
  }

  /**
   * Present a simple confirmation prompt.
   *
   * Enforces minimum review time before accepting input.
   * Returns ChallengeResult with passed=true if the operator confirms
   * with "y" or "yes".
   */
  async present(
    ctx: ActionContext,
    risk: RiskAssessment
  ): Promise<ChallengeResult> {
    const start = performance.now();
    const print = this._printFn;

    // -- render action summary ------------------------------------------
    const separator = "=".repeat(60);
    print(`\n${separator}`);
    print(`  Action: ${ctx.functionName}`);
    print(
      `  Risk: ${risk.level.toUpperCase()} (${risk.score.toFixed(2)})`
    );
    if (ctx.functionDoc) {
      print(`  Description: ${ctx.functionDoc}`);
    }
    print(`  Call: ${describeAction(ctx)}`);
    print(separator);

    // -- enforce minimum review time ------------------------------------
    const elapsed = (performance.now() - start) / 1000;
    if (elapsed < this.minReviewSeconds) {
      const remaining = this.minReviewSeconds - elapsed;
      print(
        `  [Review for ${Math.round(remaining)}s before approving...]`
      );
      await sleep(remaining);
    }

    // -- collect response -----------------------------------------------
    print("  Approve? [y/N]: ");
    const response = (await this._promptFn()).trim().toLowerCase();
    const totalElapsed = (performance.now() - start) / 1000;

    const approved = response === "y" || response === "yes";
    return createChallengeResult({
      passed: approved,
      challengeType: this.challengeType,
      responseTimeSeconds: totalElapsed,
      questionsAsked: 1,
      questionsCorrect: approved ? 1 : 0,
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

async function defaultPrompt(): Promise<string> {
  const { createInterface } = await import("node:readline");
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<string>((resolve) => {
    rl.question("", (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function sleep(seconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}
