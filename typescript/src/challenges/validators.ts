/**
 * Pluggable validators for teach-back challenge responses.
 *
 * Provides the TeachBackValidator interface and the built-in
 * KeywordValidator (word-count + key-term overlap).
 */

import * as pathModule from "node:path";
import type { ActionContext } from "../types.js";

// ---------------------------------------------------------------------------
// TeachBackValidator interface
// ---------------------------------------------------------------------------

/**
 * Interface for validating teach-back explanations.
 *
 * Implementations receive the operator's free-text explanation and the
 * ActionContext, and return `{ passed, notes }`.
 */
export interface TeachBackValidator {
  validate(
    explanation: string,
    context: ActionContext
  ): Promise<{ passed: boolean; notes: string }>;
}

// ---------------------------------------------------------------------------
// Key term extraction (shared utility)
// ---------------------------------------------------------------------------

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
  const allValues: unknown[] = [...ctx.args, ...Object.values(ctx.kwargs)];
  for (const val of allValues) {
    if (typeof val === "string" && val.length > 2) {
      if (val.includes("/") || val.includes("\\")) {
        terms.push(pathModule.basename(val).toLowerCase());
      }
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
// KeywordValidator
// ---------------------------------------------------------------------------

/**
 * Default validator using word count and key-term overlap.
 */
export class KeywordValidator implements TeachBackValidator {
  readonly minWords: number;

  constructor(options?: { minWords?: number }) {
    this.minWords = options?.minWords ?? 15;
  }

  async validate(
    explanation: string,
    context: ActionContext
  ): Promise<{ passed: boolean; notes: string }> {
    const notesList: string[] = [];

    // Word count check
    const wordCount = explanation.split(/\s+/).filter(Boolean).length;
    const lengthOk = wordCount >= this.minWords;
    if (!lengthOk) {
      notesList.push(
        `Too short: ${wordCount} words (minimum ${this.minWords}).`
      );
    }

    // Key-term overlap check
    const keyTerms = extractKeyTerms(context);
    const explanationLower = explanation.toLowerCase();
    const matchedTerms = keyTerms.filter((t) => explanationLower.includes(t));
    const termsOk = matchedTerms.length >= 1;
    if (!termsOk) {
      notesList.push(
        "No key terms from the action context found in explanation. " +
          `Expected at least one of: ${JSON.stringify(keyTerms.slice(0, 6))}`
      );
    } else {
      notesList.push(`Matched key terms: ${JSON.stringify(matchedTerms)}`);
    }

    const passed = lengthOk && termsOk;
    return {
      passed,
      notes:
        notesList.length > 0
          ? notesList.join("; ")
          : "Keyword validation passed.",
    };
  }
}
