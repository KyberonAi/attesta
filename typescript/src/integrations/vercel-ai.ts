/**
 * Vercel AI SDK integration for attesta.
 *
 * Provides middleware and tool wrappers that integrate attesta
 * approval flows into Vercel AI SDK (ai package) pipelines.
 *
 * Requires "ai" as a peer dependency.
 */

import {
  type ApprovalResult,
  Verdict,
  createActionContext,
} from "../types.js";
import { Attesta, AttestaDenied } from "../gate.js";
import type { AttestaOptions } from "../gate.js";

// ---------------------------------------------------------------------------
// Types for Vercel AI SDK interop (avoid hard dependency)
// ---------------------------------------------------------------------------

/**
 * Minimal interface matching a Vercel AI SDK tool definition.
 */
interface VercelAIToolLike {
  description?: string;
  parameters?: unknown;
  execute?: (...args: unknown[]) => Promise<unknown>;
}

// ---------------------------------------------------------------------------
// GatedVercelTool options
// ---------------------------------------------------------------------------

/**
 * Options for wrapping a Vercel AI SDK tool with attesta approval.
 */
export interface GatedVercelToolOptions extends AttestaOptions {
  /** Agent ID to attach to every action context. */
  agentId?: string;

  /** Session ID to attach to every action context. */
  sessionId?: string;

  /** Environment (e.g. "production"). */
  environment?: string;

  /** Extra metadata. */
  metadata?: Record<string, unknown>;

  /**
   * Callback invoked when an action is denied.
   * By default, throws a AttestaDenied error.
   */
  onDenied?: (result: ApprovalResult) => unknown | Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Tool wrapper
// ---------------------------------------------------------------------------

/**
 * Wrap a Vercel AI SDK tool definition with attesta approval.
 *
 * The wrapped tool runs the full gate evaluation pipeline before
 * delegating to the original tool's execute function.
 *
 * ```ts
 * import { tool } from "ai";
 * import { z } from "zod";
 * import { gatedVercelTool } from "@attesta/core/integrations";
 *
 * const deleteTool = tool({
 *   description: "Delete a file",
 *   parameters: z.object({ path: z.string() }),
 *   execute: async ({ path }) => { ... },
 * });
 *
 * const safeTool = gatedVercelTool("deleteFile", deleteTool, {
 *   riskHints: { destructive: true },
 * });
 * ```
 */
export function gatedVercelTool<T extends VercelAIToolLike>(
  name: string,
  tool: T,
  options: GatedVercelToolOptions = {}
): T {
  const attestaInstance = new Attesta({
    riskScorer: options.riskScorer,
    renderer: options.renderer,
    auditLogger: options.auditLogger,
    challengeMap: options.challengeMap,
    minReviewSeconds: options.minReviewSeconds,
    riskOverride: options.riskOverride,
    riskHints: options.riskHints,
  });

  const originalExecute = tool.execute;
  if (typeof originalExecute !== "function") {
    return tool; // Nothing to wrap if there's no execute function
  }

  const wrappedExecute = async (
    ...args: unknown[]
  ): Promise<unknown> => {
    const ctx = createActionContext({
      functionName: name,
      args,
      kwargs: typeof args[0] === "object" && args[0] !== null
        ? (args[0] as Record<string, unknown>)
        : {},
      functionDoc: tool.description,
      hints: { ...(options.riskHints ?? {}) },
      agentId: options.agentId,
      sessionId: options.sessionId,
      environment: options.environment ?? "development",
      metadata: { ...(options.metadata ?? {}) },
    });

    const result = await attestaInstance.evaluate(ctx);

    if (
      result.verdict === Verdict.DENIED ||
      result.verdict === Verdict.TIMED_OUT ||
      result.verdict === Verdict.ESCALATED
    ) {
      if (options.onDenied) {
        return options.onDenied(result);
      }
      throw new AttestaDenied(
        `Action "${name}" denied by attesta. ` +
          `Risk: ${result.riskAssessment.level} (${result.riskAssessment.score.toFixed(2)}).`,
        { result }
      );
    }

    return originalExecute.apply(tool, args);
  };

  // Create a shallow copy with the wrapped execute
  return {
    ...tool,
    execute: wrappedExecute,
  };
}

// ---------------------------------------------------------------------------
// Middleware for Vercel AI SDK generateText / streamText
// ---------------------------------------------------------------------------

/**
 * Options for the attesta middleware.
 */
export interface AttestaMiddlewareOptions extends AttestaOptions {
  /** Agent ID. */
  agentId?: string;

  /** Session ID. */
  sessionId?: string;

  /** Environment. */
  environment?: string;

  /** Extra metadata. */
  metadata?: Record<string, unknown>;

  /**
   * Function to extract the action name from the tool call.
   * Defaults to using the tool name directly.
   */
  getActionName?: (toolName: string, args: unknown) => string;
}

/**
 * Create an attesta middleware for Vercel AI SDK tool calls.
 *
 * Returns an object with `onToolCall` that can be spread into
 * generateText / streamText options to intercept tool calls
 * with attesta approval.
 *
 * ```ts
 * import { generateText } from "ai";
 * import { createAttestaMiddleware } from "@attesta/core/integrations";
 *
 * const attesta = createAttestaMiddleware({
 *   riskHints: { pii: true },
 *   agentId: "my-agent",
 * });
 *
 * const result = await generateText({
 *   model,
 *   tools: { ... },
 *   ...attesta,
 * });
 * ```
 */
export function createAttestaMiddleware(
  options: AttestaMiddlewareOptions = {}
): {
  experimental_onToolCall: (params: {
    toolCall: { toolName: string; args: unknown };
  }) => Promise<void>;
} {
  const attestaInstance = new Attesta({
    riskScorer: options.riskScorer,
    renderer: options.renderer,
    auditLogger: options.auditLogger,
    challengeMap: options.challengeMap,
    minReviewSeconds: options.minReviewSeconds,
    riskOverride: options.riskOverride,
    riskHints: options.riskHints,
  });

  const getActionName =
    options.getActionName ?? ((toolName: string) => toolName);

  return {
    experimental_onToolCall: async (params: {
      toolCall: { toolName: string; args: unknown };
    }): Promise<void> => {
      const { toolName, args } = params.toolCall;
      const actionName = getActionName(toolName, args);

      const ctx = createActionContext({
        functionName: actionName,
        args: [args],
        kwargs:
          typeof args === "object" && args !== null
            ? (args as Record<string, unknown>)
            : {},
        hints: { ...(options.riskHints ?? {}) },
        agentId: options.agentId,
        sessionId: options.sessionId,
        environment: options.environment ?? "development",
        metadata: {
          ...(options.metadata ?? {}),
          vercelToolName: toolName,
        },
      });

      const result = await attestaInstance.evaluate(ctx);

      if (
        result.verdict === Verdict.DENIED ||
        result.verdict === Verdict.TIMED_OUT ||
        result.verdict === Verdict.ESCALATED
      ) {
        throw new AttestaDenied(
          `Tool call "${toolName}" denied by attesta. ` +
            `Risk: ${result.riskAssessment.level} (${result.riskAssessment.score.toFixed(2)}).`,
          { result }
        );
      }
    },
  };
}
