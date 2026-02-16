/**
 * Terminal renderer for attesta.
 *
 * Provides a rich terminal UI for presenting gates to the operator.
 * Uses chalk (optional peer dependency) for colored output. Falls back
 * to plain text if chalk is not installed.
 */

import {
  type ActionContext,
  type ChallengeResult,
  ChallengeType,
  type Renderer,
  type RiskAssessment,
  Verdict,
  createChallengeResult,
  describeAction,
} from "../types.js";

// ---------------------------------------------------------------------------
// Lazy chalk import
// ---------------------------------------------------------------------------

interface ChalkLike {
  bold: ChalkLike & ((text: string) => string);
  red: ChalkLike & ((text: string) => string);
  yellow: ChalkLike & ((text: string) => string);
  green: ChalkLike & ((text: string) => string);
  blue: ChalkLike & ((text: string) => string);
  cyan: ChalkLike & ((text: string) => string);
  gray: ChalkLike & ((text: string) => string);
  dim: ChalkLike & ((text: string) => string);
  bgRed: ChalkLike & ((text: string) => string);
  bgYellow: ChalkLike & ((text: string) => string);
  bgGreen: ChalkLike & ((text: string) => string);
  white: ChalkLike & ((text: string) => string);
}

/** Identity chalk that just returns the input string. */
function identity(text: string): string {
  return text;
}

function createNoopChalk(): ChalkLike {
  const handler: ProxyHandler<(text: string) => string> = {
    get(_target, _prop) {
      return new Proxy(identity, handler);
    },
    apply(_target, _thisArg, argArray: unknown[]) {
      return (argArray[0] as string) ?? "";
    },
  };
  return new Proxy(identity, handler) as unknown as ChalkLike;
}

let _chalk: ChalkLike | undefined;

async function getChalk(): Promise<ChalkLike> {
  if (_chalk) return _chalk;
  try {
    const mod = await import("chalk");
    _chalk = (mod.default ?? mod) as unknown as ChalkLike;
    return _chalk;
  } catch {
    _chalk = createNoopChalk();
    return _chalk;
  }
}

// ---------------------------------------------------------------------------
// Risk level colors
// ---------------------------------------------------------------------------

function riskColor(
  chalk: ChalkLike,
  level: string
): (text: string) => string {
  switch (level) {
    case "low":
      return (t: string) => chalk.green(t);
    case "medium":
      return (t: string) => chalk.yellow(t);
    case "high":
      return (t: string) => chalk.red(t);
    case "critical":
      return (t: string) => chalk.bgRed.white.bold(t);
    default:
      return (t: string) => chalk.gray(t);
  }
}

// ---------------------------------------------------------------------------
// TerminalRenderer options
// ---------------------------------------------------------------------------

/**
 * Options for configuring the TerminalRenderer.
 */
export interface TerminalRendererOptions {
  /** Custom input function. Signature: (prompt: string) => Promise<string>. */
  promptFn?: (prompt: string) => Promise<string>;

  /** Custom output function. */
  printFn?: (message: string) => void;

  /** Whether to use colored output (default true, falls back if chalk unavailable). */
  useColor?: boolean;
}

// ---------------------------------------------------------------------------
// TerminalRenderer
// ---------------------------------------------------------------------------

/**
 * Rich terminal renderer for presenting gates to the operator.
 *
 * Uses chalk for colored output when available. Falls back to plain text
 * output when chalk is not installed.
 */
export class TerminalRenderer implements Renderer {
  private readonly _promptFn: (prompt: string) => Promise<string>;
  private readonly _printFn: (message: string) => void;
  private readonly _useColor: boolean;

  constructor(options: TerminalRendererOptions = {}) {
    this._promptFn = options.promptFn ?? defaultPrompt;
    this._printFn = options.printFn ?? defaultPrint;
    this._useColor = options.useColor ?? true;
  }

  async renderApproval(
    ctx: ActionContext,
    risk: RiskAssessment
  ): Promise<Verdict> {
    const chalk = this._useColor
      ? await getChalk()
      : createNoopChalk();
    const print = this._printFn;
    const colorize = riskColor(chalk, risk.level);

    const separator = chalk.dim("=".repeat(60));
    print(`\n${separator}`);
    print(
      `  ${chalk.bold("Action:")} ${ctx.functionName}`
    );
    print(
      `  ${chalk.bold("Risk:")}   ${colorize(risk.level.toUpperCase())} (${risk.score.toFixed(2)})`
    );
    if (ctx.functionDoc) {
      print(`  ${chalk.bold("Desc:")}   ${ctx.functionDoc}`);
    }
    print(`  ${chalk.bold("Call:")}   ${describeAction(ctx)}`);
    print(separator);

    print(
      `  ${chalk.bold("Approve?")} [${chalk.green("y")}/${chalk.red("N")}]: `
    );
    const response = (await this._promptFn("")).trim().toLowerCase();
    const approved = response === "y" || response === "yes";

    if (approved) {
      print(chalk.green("  Approved."));
      return Verdict.APPROVED;
    } else {
      print(chalk.red("  Denied."));
      return Verdict.DENIED;
    }
  }

  async renderChallenge(
    ctx: ActionContext,
    risk: RiskAssessment,
    challengeType: ChallengeType
  ): Promise<ChallengeResult> {
    if (challengeType === ChallengeType.TEACH_BACK) {
      return this._renderTeachBack(ctx, risk);
    }
    if (challengeType === ChallengeType.QUIZ) {
      return this._renderQuiz(ctx, risk);
    }
    if (challengeType === ChallengeType.MULTI_PARTY) {
      return this._renderMultiParty(ctx, risk);
    }
    // CONFIRM and unknown types: Y/N confirmation
    return this._renderConfirm(ctx, risk, challengeType);
  }

  private async _renderConfirm(
    ctx: ActionContext,
    risk: RiskAssessment,
    challengeType: ChallengeType,
  ): Promise<ChallengeResult> {
    const chalk = this._useColor
      ? await getChalk()
      : createNoopChalk();
    const print = this._printFn;
    const colorize = riskColor(chalk, risk.level);

    const separator = chalk.dim("=".repeat(60));
    print(`\n${separator}`);
    print(
      `  ${chalk.bold(`CHALLENGE: ${challengeType.toUpperCase()}`)}`
    );
    print(separator);
    this._printActionDetails(chalk, print, colorize, ctx, risk);
    print(separator);

    print(
      `  ${chalk.bold("Approve?")} [${chalk.green("y")}/${chalk.red("N")}]: `
    );
    const response = (await this._promptFn("")).trim().toLowerCase();
    const approved = response === "y" || response === "yes";

    if (approved) {
      print(chalk.green("  Challenge passed."));
    } else {
      print(chalk.red("  Challenge failed."));
    }

    return createChallengeResult({
      passed: approved,
      challengeType,
      questionsAsked: 1,
      questionsCorrect: approved ? 1 : 0,
    });
  }

  private async _renderQuiz(
    ctx: ActionContext,
    risk: RiskAssessment,
  ): Promise<ChallengeResult> {
    const chalk = this._useColor
      ? await getChalk()
      : createNoopChalk();
    const print = this._printFn;
    const colorize = riskColor(chalk, risk.level);

    const separator = chalk.dim("=".repeat(60));
    print(`\n${separator}`);
    print(`  ${chalk.bold("QUIZ CHALLENGE -- HIGH RISK")}`);
    print(separator);
    this._printActionDetails(chalk, print, colorize, ctx, risk);
    print(separator);

    // Generate a comprehension question based on the action
    const question = `What will '${ctx.functionName}' do in this context?`;
    print(`\n  ${chalk.bold("Comprehension Check:")}`);
    print(`  ${question}`);
    print(`  ${chalk.dim("(Provide a non-empty answer to pass)")}`);
    const answer = (await this._promptFn("  > ")).trim();

    const passed = answer.length > 0;
    if (passed) {
      print(chalk.green("  Quiz passed."));
    } else {
      print(chalk.red("  No answer provided -- DENIED."));
    }

    return createChallengeResult({
      passed,
      challengeType: ChallengeType.QUIZ,
      questionsAsked: 1,
      questionsCorrect: passed ? 1 : 0,
      details: { question, answer },
    });
  }

  private async _renderTeachBack(
    ctx: ActionContext,
    risk: RiskAssessment,
  ): Promise<ChallengeResult> {
    const chalk = this._useColor
      ? await getChalk()
      : createNoopChalk();
    const print = this._printFn;
    const colorize = riskColor(chalk, risk.level);

    const separator = chalk.dim("=".repeat(60));
    print(`\n${separator}`);
    print(`  ${chalk.bold("TEACH-BACK CHALLENGE -- CRITICAL RISK")}`);
    print(separator);
    this._printActionDetails(chalk, print, colorize, ctx, risk);
    print(separator);

    print(`\n  ${chalk.bold("Explain what this action will do and its effects:")}`);
    print(`  ${chalk.dim("(minimum 15 words)")}`);
    const explanation = (await this._promptFn("  > ")).trim();

    const wordCount = explanation.split(/\s+/).filter(Boolean).length;
    const passed = wordCount >= 15;

    if (passed) {
      print(chalk.green(`  Teach-back accepted (${wordCount} words).`));
    } else {
      print(chalk.red(
        `  Insufficient explanation (${wordCount}/15 words) -- DENIED.`
      ));
    }

    return createChallengeResult({
      passed,
      challengeType: ChallengeType.TEACH_BACK,
      questionsAsked: 1,
      questionsCorrect: passed ? 1 : 0,
      details: { explanation, wordCount },
    });
  }

  private async _renderMultiParty(
    ctx: ActionContext,
    risk: RiskAssessment,
  ): Promise<ChallengeResult> {
    const chalk = this._useColor
      ? await getChalk()
      : createNoopChalk();
    const print = this._printFn;
    const colorize = riskColor(chalk, risk.level);
    const requiredApprovers = 2;

    const separator = chalk.dim("=".repeat(60));
    print(`\n${separator}`);
    print(`  ${chalk.bold("MULTI-PARTY APPROVAL REQUIRED")}`);
    print(separator);
    this._printActionDetails(chalk, print, colorize, ctx, risk);
    print(
      `  ${chalk.bold(`This action requires approval from ${requiredApprovers} independent reviewers.`)}`
    );
    print(separator);

    let approvals = 0;
    for (let i = 0; i < requiredApprovers; i++) {
      print(`\n  ${chalk.bold(`--- Reviewer ${i + 1} of ${requiredApprovers} ---`)}`);
      const response = (
        await this._promptFn(`  Reviewer ${i + 1} [a]pprove / [d]eny: `)
      ).trim().toLowerCase();
      if (response === "a" || response === "approve" || response === "y" || response === "yes") {
        approvals++;
        print(chalk.green(`  Reviewer ${i + 1}: APPROVED`));
      } else {
        print(chalk.red(`  Reviewer ${i + 1}: DENIED`));
      }
    }

    const passed = approvals >= requiredApprovers;
    if (passed) {
      print(chalk.green(`\n  All ${requiredApprovers} reviewers approved.`));
    } else {
      print(chalk.red(
        `\n  Multi-party approval FAILED (${approvals}/${requiredApprovers} approved).`
      ));
    }

    return createChallengeResult({
      passed,
      challengeType: ChallengeType.MULTI_PARTY,
      questionsAsked: requiredApprovers,
      questionsCorrect: approvals,
      details: { requiredApprovers, approvals },
    });
  }

  private _printActionDetails(
    chalk: ChalkLike,
    print: (msg: string) => void,
    colorize: (text: string) => string,
    ctx: ActionContext,
    risk: RiskAssessment,
  ): void {
    print(`  ${chalk.bold("Action:")} ${ctx.functionName}`);
    print(
      `  ${chalk.bold("Risk:")}   ${colorize(risk.level.toUpperCase())} (${risk.score.toFixed(2)})`
    );
    if (ctx.functionDoc) {
      print(`  ${chalk.bold("Desc:")}   ${ctx.functionDoc}`);
    }
    print(`  ${chalk.bold("Call:")}   ${describeAction(ctx)}`);
    if (risk.factors.length > 0) {
      print(`  ${chalk.bold("Risk factors:")}`);
      for (const factor of risk.factors) {
        print(`    ${chalk.dim("-")} ${factor.name}: ${factor.description}`);
      }
    }
  }

  async renderInfo(message: string): Promise<void> {
    const chalk = this._useColor
      ? await getChalk()
      : createNoopChalk();
    this._printFn(chalk.blue(`  [info] ${message}`));
  }

  async renderAutoApproved(
    ctx: ActionContext,
    risk: RiskAssessment
  ): Promise<void> {
    const chalk = this._useColor
      ? await getChalk()
      : createNoopChalk();
    this._printFn(
      chalk.dim(
        `  [auto-approved] ${ctx.functionName} (risk=${risk.score.toFixed(2)})`
      )
    );
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
