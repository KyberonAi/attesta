/**
 * Integration modules for attesta.
 *
 * Each integration adapts the attesta approval pipeline for a specific
 * AI framework. All integrations have their framework dependencies as
 * optional peer dependencies.
 */

export { gatedTool, createGateNode } from "./langchain.js";
export type { GatedToolOptions } from "./langchain.js";

export {
  gatedVercelTool,
  createAttestaMiddleware,
} from "./vercel-ai.js";
export type {
  GatedVercelToolOptions,
  AttestaMiddlewareOptions,
} from "./vercel-ai.js";
