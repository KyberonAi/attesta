/**
 * LangChain / LangGraph integration for attesta.
 *
 * Provides a tool wrapper and callback handler that integrates attesta
 * approval flows into LangChain agent pipelines.
 *
 * Requires @langchain/core as a peer dependency.
 */

import {
  type ApprovalResult,
  Verdict,
  createActionContext,
  describeAction,
} from "../types.js";
import { Attesta, AttestaDenied } from "../gate.js";
import type { AttestaOptions } from "../gate.js";

// ---------------------------------------------------------------------------
// Types for LangChain interop (avoid hard dependency)
// ---------------------------------------------------------------------------

/**
 * Minimal interface matching @langchain/core StructuredTool.
 * We avoid importing from @langchain/core directly to keep it optional.
 */
interface LangChainToolLike {
  name: string;
  description: string;
  invoke(input: unknown, config?: unknown): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// GatedTool wrapper
// ---------------------------------------------------------------------------

/**
 * Options for wrapping a LangChain tool with attesta approval.
 */
export interface GatedToolOptions extends AttestaOptions {
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
   * By default, the denied result is returned as a string message.
   */
  onDenied?: (result: ApprovalResult) => string | Promise<string>;
}

/**
 * Wrap a LangChain tool with attesta approval.
 *
 * The wrapped tool runs the full gate evaluation pipeline before
 * delegating to the original tool. If the action is denied, the
 * tool returns a denial message instead of throwing.
 *
 * ```ts
 * import { WikipediaQueryRun } from "@langchain/community/tools/wikipedia_query";
 * import { gatedTool } from "@attesta/core/integrations";
 *
 * const wiki = new WikipediaQueryRun();
 * const safeWiki = gatedTool(wiki, { riskHints: { pii: false } });
 * ```
 */
export function gatedTool<T extends LangChainToolLike>(
  tool: T,
  options: GatedToolOptions = {}
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

  const defaultOnDenied = (result: ApprovalResult): string =>
    `[ATTESTA] Action "${tool.name}" was denied. ` +
    `Risk: ${result.riskAssessment.level} (${result.riskAssessment.score.toFixed(2)}). ` +
    `Verdict: ${result.verdict}.`;

  const onDenied = options.onDenied ?? defaultOnDenied;

  // Create a proxy that intercepts the invoke method.
  const proxy = new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke") {
        return async (input: unknown, config?: unknown): Promise<unknown> => {
          const ctx = createActionContext({
            functionName: tool.name,
            args: [input],
            kwargs: {},
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
            return onDenied(result);
          }

          return target.invoke(input, config);
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });

  return proxy;
}

// ---------------------------------------------------------------------------
// LangGraph node helper
// ---------------------------------------------------------------------------

/**
 * Create a LangGraph-compatible gate node.
 *
 * Returns an async function suitable for use as a node in a LangGraph
 * StateGraph. The node evaluates the gate and either passes through
 * or blocks the state update.
 *
 * ```ts
 * import { StateGraph } from "@langchain/langgraph";
 * import { createGateNode } from "@attesta/core/integrations";
 *
 * const gateNode = createGateNode({
 *   riskOverride: "high",
 *   agentId: "my-agent",
 * });
 *
 * const graph = new StateGraph(...)
 *   .addNode("gate", gateNode)
 *   ...
 * ```
 */
export function createGateNode(
  options: GatedToolOptions & {
    /** Name of the action (used in ActionContext). */
    actionName?: string;
  } = {}
): (state: Record<string, unknown>) => Promise<Record<string, unknown>> {
  const attestaInstance = new Attesta({
    riskScorer: options.riskScorer,
    renderer: options.renderer,
    auditLogger: options.auditLogger,
    challengeMap: options.challengeMap,
    minReviewSeconds: options.minReviewSeconds,
    riskOverride: options.riskOverride,
    riskHints: options.riskHints,
  });

  return async (
    state: Record<string, unknown>
  ): Promise<Record<string, unknown>> => {
    const ctx = createActionContext({
      functionName: options.actionName ?? "langgraph_node",
      args: [],
      kwargs: state,
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
      throw new AttestaDenied(
        `LangGraph gate denied: ${describeAction(ctx)}`,
        { result }
      );
    }

    // Pass through state with gate result metadata
    return {
      ...state,
      _attesta: {
        verdict: result.verdict,
        riskScore: result.riskAssessment.score,
        riskLevel: result.riskAssessment.level,
        auditEntryId: result.auditEntryId,
      },
    };
  };
}
