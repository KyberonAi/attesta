/**
 * @attesta/core
 *
 * Human-in-the-loop approval framework for AI agent actions.
 *
 * This is the main entry point that re-exports all public types,
 * classes, and functions from the core library.
 *
 * @example
 * ```ts
 * import { gate, Attesta, RiskLevel, DefaultRiskScorer } from "@attesta/core";
 *
 * // Wrap a function with attesta approval (simplest usage)
 * const safeFn = gate(myDangerousFunction);
 *
 * // Configure with options
 * const safeFn = gate({ risk: "high", environment: "production" })(myFn);
 *
 * // Use the Attesta class directly for full control
 * const g = new Attesta({
 *   riskScorer: new DefaultRiskScorer(),
 *   renderer: myRenderer,
 *   auditLogger: myAuditLogger,
 * });
 * const result = await g.evaluate(ctx);
 * ```
 */

// -- Types & enums ----------------------------------------------------------

export {
  // Enums (const objects + types)
  RiskLevel,
  Verdict,
  ChallengeType,

  // Factory functions
  riskLevelFromScore,
  createActionContext,
  createRiskAssessment,
  createChallengeResult,
  createApprovalResult,
  describeAction,
} from "./types.js";

export type {
  // Data interfaces
  ActionContext,
  RiskFactor,
  RiskAssessment,
  ChallengeResult,
  ApprovalResult,

  // Protocol interfaces
  RiskScorer,
  ChallengeProtocol,
  Renderer,
  AuditLoggerProtocol,
  TeachBackValidatorProtocol,
} from "./types.js";

// -- Attesta ----------------------------------------------------------------

export {
  Attesta,
  AttestaDenied,
  gate,
  gateDecorator,
  getAttesta,
} from "./gate.js";

export type { AttestaOptions, AttestaDecoratorOptions } from "./gate.js";

// -- Risk -------------------------------------------------------------------

export {
  DefaultRiskScorer,
  CompositeRiskScorer,
  MaxRiskScorer,
  FixedRiskScorer,
} from "./risk.js";

export type {
  DefaultRiskScorerOptions,
  ScorerWeight,
} from "./risk.js";

// -- Trust ------------------------------------------------------------------

export { TrustEngine } from "./trust.js";

export type {
  TrustRecord,
  TrustProfile,
  TrustEngineOptions,
} from "./trust.js";

// -- Audit ------------------------------------------------------------------

export {
  AuditLogger,
  buildEntry,
  createAuditEntry,
  auditEntryToJson,
  auditEntryFromJson,
  computeEntryHash,
  computeEntryHashAsync,
} from "./audit.js";

export type {
  AuditEntryData,
  ChainVerification,
  AuditQueryFilters,
} from "./audit.js";

// -- Challenges (re-exported for convenience) --------------------------------

export {
  ConfirmChallenge,
  QuizChallenge,
  TeachBackChallenge,
  KeywordValidator,
} from "./challenges/index.js";

export type {
  ConfirmChallengeOptions,
  QuizChallengeOptions,
  Question,
  TeachBackChallengeOptions,
  TeachBackValidator,
} from "./challenges/index.js";

// -- Renderers (re-exported for convenience) ---------------------------------

export { TerminalRenderer } from "./renderers/index.js";
export type { TerminalRendererOptions } from "./renderers/index.js";

export { WebRenderer } from "./renderers/web.js";
export type { WebRendererOptions } from "./renderers/web.js";

// -- Events -----------------------------------------------------------------

export { EventBus, EventType, createEvent } from "./events.js";
export type { Event, EventHandler, AsyncEventHandler } from "./events.js";

// -- Environment ------------------------------------------------------------

export {
  Environment,
  detectEnvironment,
  RISK_MULTIPLIERS,
} from "./environment.js";

// -- Exporters --------------------------------------------------------------

export { CSVExporter, JSONExporter, DEFAULT_COLUMNS } from "./exporters.js";
export type { AuditExporter } from "./exporters.js";

// -- Webhooks ---------------------------------------------------------------

export { WebhookDispatcher } from "./webhooks.js";
export type { WebhookConfig } from "./webhooks.js";
