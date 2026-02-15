/**
 * Quiz challenge for HIGH-risk actions.
 *
 * Generates 1-3 comprehension questions derived from the actual action
 * parameters so the operator must demonstrate they understand what is
 * about to happen before approving.
 */

import * as path from "node:path";

import {
  type ActionContext,
  type ChallengeProtocol,
  type ChallengeResult,
  ChallengeType,
  type RiskAssessment,
  createChallengeResult,
  describeAction,
} from "../types.js";

// ---------------------------------------------------------------------------
// Question model
// ---------------------------------------------------------------------------

/**
 * A single quiz question presented to the operator.
 */
export interface Question {
  /** The question text shown to the operator. */
  text: string;

  /** The canonical correct answer (case-insensitive comparison). */
  correctAnswer: string;

  /**
   * null for free-text input, or a list of choices for multiple-choice
   * (the correct answer must appear in the list).
   */
  options: string[] | null;
}

// ---------------------------------------------------------------------------
// Helpers for question generation
// ---------------------------------------------------------------------------

const PATH_RE =
  /(?:\/(?:[a-zA-Z0-9._\-]+\/)*[a-zA-Z0-9._\-]+)|(?:[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+)|(?:(?:\.\.\/|\.\/)(?:[a-zA-Z0-9._\-]+\/)*[a-zA-Z0-9._\-]+)/g;

const SQL_TABLE_RE =
  /(?:FROM|INTO|UPDATE|TABLE|JOIN)\s+[`"']?(\w+)[`"']?/gi;

const NUMERIC_RE = /^-?\d+(?:\.\d+)?$/;

interface NamedValue {
  name: string | null;
  value: unknown;
}

function flattenArgs(ctx: ActionContext): NamedValue[] {
  const items: NamedValue[] = ctx.args.map((a) => ({
    name: null,
    value: a,
  }));
  for (const [key, val] of Object.entries(ctx.kwargs)) {
    items.push({ name: key, value: val });
  }
  return items;
}

function findPaths(values: NamedValue[]): string[] {
  const paths: string[] = [];
  for (const { value } of values) {
    if (typeof value === "string") {
      PATH_RE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = PATH_RE.exec(value)) !== null) {
        paths.push(match[0]);
      }
    }
  }
  return paths;
}

function findNumbers(values: NamedValue[]): Array<{ name: string | null; numStr: string }> {
  const results: Array<{ name: string | null; numStr: string }> = [];
  for (const { name, value } of values) {
    if (typeof value === "number" && !isNaN(value)) {
      results.push({ name, numStr: String(value) });
    } else if (typeof value === "string" && NUMERIC_RE.test(value)) {
      results.push({ name, numStr: value });
    }
  }
  return results;
}

function findSqlTables(values: NamedValue[]): string[] {
  const tables: string[] = [];
  const seen = new Set<string>();
  for (const { value } of values) {
    if (typeof value === "string") {
      SQL_TABLE_RE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = SQL_TABLE_RE.exec(value)) !== null) {
        const table = match[1];
        if (!seen.has(table)) {
          seen.add(table);
          tables.push(table);
        }
      }
    }
  }
  return tables;
}

function splitFunctionName(name: string): string[] {
  // Split on underscores first
  const parts = name.replace(/-/g, "_").split("_");
  // Then split camelCase/PascalCase within each part
  const words: string[] = [];
  for (const part of parts) {
    const tokens = part.replace(/([a-z])([A-Z])/g, "$1 $2").split(/\s+/);
    for (const t of tokens) {
      if (t) words.push(t.toLowerCase());
    }
  }
  return words;
}

function shuffleArray<T>(arr: T[]): T[] {
  const result = [...arr];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

// ---------------------------------------------------------------------------
// QuizChallenge options
// ---------------------------------------------------------------------------

/**
 * Options for configuring the QuizChallenge.
 */
export interface QuizChallengeOptions {
  /** Upper bound on the number of questions to generate (1-3). Default 3. */
  maxQuestions?: number;

  /** Minimum correct answers required to pass. Default 1. */
  minCorrect?: number;

  /** Minimum wall-clock seconds before the first question is shown. Default 10. */
  minReviewSeconds?: number;

  /** Custom input function. Signature: (prompt: string) => Promise<string>. */
  promptFn?: (prompt: string) => Promise<string>;

  /** Custom output function. */
  printFn?: (message: string) => void;
}

// ---------------------------------------------------------------------------
// QuizChallenge
// ---------------------------------------------------------------------------

/**
 * Comprehension quiz for HIGH-risk actions.
 *
 * Analyses the ActionContext to programmatically generate 1-3
 * multiple-choice or fill-in-the-blank questions about the pending action.
 * The operator must answer at least minCorrect questions correctly to pass.
 */
export class QuizChallenge implements ChallengeProtocol {
  readonly maxQuestions: number;
  readonly minCorrect: number;
  readonly minReviewSeconds: number;
  private readonly _promptFn: (prompt: string) => Promise<string>;
  private readonly _printFn: (message: string) => void;

  constructor(options: QuizChallengeOptions = {}) {
    this.maxQuestions = Math.max(1, Math.min(options.maxQuestions ?? 3, 3));
    this.minCorrect = Math.max(1, options.minCorrect ?? 1);
    this.minReviewSeconds = options.minReviewSeconds ?? 10.0;
    this._promptFn = options.promptFn ?? defaultPrompt;
    this._printFn = options.printFn ?? defaultPrint;
  }

  get challengeType(): ChallengeType {
    return ChallengeType.QUIZ;
  }

  // -- question generation -----------------------------------------------

  /**
   * Build a list of questions from the action context.
   *
   * Strategy priority:
   * 1. File-path arguments   -> "What directory / file will be affected?"
   * 2. Numeric arguments     -> "What is the value of <param>?"
   * 3. SQL-like strings      -> "Which table will be affected?"
   * 4. Fallback              -> "What will this function do?" (from name)
   */
  generateQuestions(
    ctx: ActionContext,
    _risk: RiskAssessment
  ): Question[] {
    const flat = flattenArgs(ctx);
    const questions: Question[] = [];

    // Strategy 1: file paths
    const paths = findPaths(flat);
    if (paths.length > 0) {
      const p = paths[0];
      const dirName = path.dirname(p) || "/";
      const baseName = path.basename(p);

      // Ask about the directory
      let wrongDirs = [
        path.dirname(path.dirname(p)) || "/",
        "/tmp",
        "/var/log",
      ];
      // Filter out correct answer and dedupe
      wrongDirs = [...new Set(wrongDirs.filter((d) => d !== dirName))];
      const dirOptions = shuffleArray([dirName, ...wrongDirs.slice(0, 3)]);

      questions.push({
        text: "What directory will be affected by this action?",
        correctAnswer: dirName,
        options: dirOptions,
      });

      // Optionally ask about the specific file
      if (questions.length < this.maxQuestions && baseName) {
        questions.push({
          text: "Which file will this action operate on?",
          correctAnswer: baseName,
          options: null, // free text
        });
      }
    }

    // Strategy 2: numeric arguments
    const numbers = findNumbers(flat);
    if (numbers.length > 0 && questions.length < this.maxQuestions) {
      const { name, numStr } = numbers[0];
      const label = name ? `parameter '${name}'` : "this action";

      let wrong: string[];
      try {
        const numVal = parseFloat(numStr);
        if (Number.isInteger(numVal)) {
          wrong = [
            String(numVal * 2),
            String(numVal + 10),
            String(Math.max(0, numVal - 1)),
          ];
        } else {
          wrong = [
            (numVal * 2).toFixed(2),
            (numVal + 10).toFixed(2),
            Math.max(0, numVal - 1).toFixed(2),
          ];
        }
      } catch {
        wrong = ["0", "100", "42"];
      }

      wrong = [...new Set(wrong.filter((w) => w !== numStr))].slice(0, 3);
      const numOptions = shuffleArray([numStr, ...wrong]);

      questions.push({
        text: `What is the numeric value for ${label}?`,
        correctAnswer: numStr,
        options: numOptions,
      });
    }

    // Strategy 3: SQL table names
    const tables = findSqlTables(flat);
    if (tables.length > 0 && questions.length < this.maxQuestions) {
      const table = tables[0];
      let wrongTables = [
        "users",
        "logs",
        "tmp_data",
        "sessions",
        "config",
      ];
      wrongTables = wrongTables
        .filter((t) => t.toLowerCase() !== table.toLowerCase())
        .slice(0, 3);
      const tableOptions = shuffleArray([table, ...wrongTables]);

      questions.push({
        text: "Which database table will be affected?",
        correctAnswer: table,
        options: tableOptions,
      });
    }

    // Strategy 4 (fallback): function-name comprehension
    if (questions.length === 0) {
      const words = splitFunctionName(ctx.functionName);
      const actionVerb = words[0] ?? "perform";
      const target =
        words.length > 1 ? words.slice(1).join(" ") : "an operation";
      const correct = `${actionVerb} ${target}`;

      let wrong = [
        `read ${target}`,
        `list ${target}`,
        `validate ${target}`,
      ];
      wrong = wrong.filter((w) => w !== correct).slice(0, 3);
      const fallbackOptions = shuffleArray([correct, ...wrong]);

      questions.push({
        text: `What will the function '${ctx.functionName}' do?`,
        correctAnswer: correct,
        options: fallbackOptions,
      });
    }

    return questions.slice(0, this.maxQuestions);
  }

  // -- presentation -------------------------------------------------------

  /**
   * Present the quiz to the operator and collect answers.
   */
  async present(
    ctx: ActionContext,
    risk: RiskAssessment
  ): Promise<ChallengeResult> {
    const start = performance.now();
    const print = this._printFn;
    const prompt = this._promptFn;

    // -- render action summary ------------------------------------------
    const separator = "=".repeat(60);
    print(`\n${separator}`);
    print("  QUIZ CHALLENGE  --  HIGH RISK ACTION");
    print(separator);
    print(`  Action: ${ctx.functionName}`);
    print(
      `  Risk:   ${risk.level.toUpperCase()} (${risk.score.toFixed(2)})`
    );
    if (ctx.functionDoc) {
      print(`  Desc:   ${ctx.functionDoc}`);
    }
    print(`  Call:   ${describeAction(ctx)}`);
    print(separator);

    // -- enforce minimum review time ------------------------------------
    const elapsed = (performance.now() - start) / 1000;
    if (elapsed < this.minReviewSeconds) {
      const remaining = this.minReviewSeconds - elapsed;
      print(
        `  [Review the action for ${Math.round(remaining)}s before answering...]`
      );
      await sleep(remaining);
    }

    // -- generate and ask questions -------------------------------------
    const questions = this.generateQuestions(ctx, risk);
    let correctCount = 0;

    for (let idx = 0; idx < questions.length; idx++) {
      const question = questions[idx];
      print(
        `\n  Question ${idx + 1}/${questions.length}: ${question.text}`
      );

      let answer: string;
      if (question.options) {
        for (let letterIdx = 0; letterIdx < question.options.length; letterIdx++) {
          const letter = String.fromCharCode(65 + letterIdx); // A, B, C, ...
          print(`    ${letter}) ${question.options[letterIdx]}`);
        }
        const raw = await prompt("  Your answer (letter or value): ");
        answer = raw.trim();

        // Accept either the letter label or the literal value
        if (
          answer.length === 1 &&
          answer.toUpperCase() >= "A" &&
          answer.toUpperCase() <= "Z"
        ) {
          const choiceIdx = answer.toUpperCase().charCodeAt(0) - 65;
          if (
            choiceIdx >= 0 &&
            choiceIdx < question.options.length
          ) {
            answer = question.options[choiceIdx];
          }
        }
      } else {
        const raw = await prompt("  Your answer: ");
        answer = raw.trim();
      }

      if (answer.toLowerCase() === question.correctAnswer.toLowerCase()) {
        correctCount++;
        print("  Correct.");
      } else {
        print(
          `  Incorrect. (expected: ${question.correctAnswer})`
        );
      }
    }

    const totalElapsed = (performance.now() - start) / 1000;
    const passed = correctCount >= this.minCorrect;

    print(
      `\n  Result: ${correctCount}/${questions.length} correct -- ${passed ? "PASSED" : "FAILED"}`
    );

    return createChallengeResult({
      passed,
      challengeType: this.challengeType,
      responseTimeSeconds: totalElapsed,
      questionsAsked: questions.length,
      questionsCorrect: correctCount,
      details: {
        questions: questions.map((q) => ({
          text: q.text,
          correctAnswer: q.correctAnswer,
          options: q.options,
        })),
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
