/**
 * Environment auto-detection and risk multipliers.
 *
 * Detects the deployment environment from environment variables, CI markers,
 * and hostname patterns. Used by the gate pipeline to adjust risk scores
 * based on the operational context.
 *
 * Detection order (first match wins):
 * 1. ATTESTA_ENV explicit override.
 * 2. CI markers: CI, GITHUB_ACTIONS, GITLAB_CI, JENKINS_URL.
 * 3. Production markers: NODE_ENV=production.
 * 4. Hostname patterns: prod-*, stg-*, staging-*.
 * 5. Default: DEVELOPMENT.
 */

import { hostname } from "node:os";

// ---------------------------------------------------------------------------
// Environment enum
// ---------------------------------------------------------------------------

export const Environment = {
  PRODUCTION: "production",
  STAGING: "staging",
  CI: "ci",
  DEVELOPMENT: "development",
} as const;

export type Environment = (typeof Environment)[keyof typeof Environment];

// ---------------------------------------------------------------------------
// Risk multipliers
// ---------------------------------------------------------------------------

/**
 * Risk multipliers per environment. Production amplifies risk, development
 * reduces it.
 */
export const RISK_MULTIPLIERS: Record<string, number> = {
  production: 1.5,
  staging: 1.2,
  ci: 1.0,
  development: 0.8,
};

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/**
 * Auto-detect the deployment environment.
 *
 * The ATTESTA_ENV environment variable always takes precedence.
 * Falls back to heuristic detection from CI markers, production
 * variables, and hostname patterns.
 */
export function detectEnvironment(): Environment {
  const env = typeof process !== "undefined" ? process.env : {};

  // 1. Explicit override
  const explicit = (env.ATTESTA_ENV ?? "").trim().toLowerCase();
  if (explicit) {
    const values = Object.values(Environment) as string[];
    if (values.includes(explicit)) {
      return explicit as Environment;
    }
  }

  // 2. CI markers
  const ciVars = [
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "CIRCLECI",
    "TRAVIS",
    "BUILDKITE",
  ];
  for (const v of ciVars) {
    if (env[v]) return Environment.CI;
  }

  // 3. Production markers
  if ((env.NODE_ENV ?? "").toLowerCase() === "production") {
    return Environment.PRODUCTION;
  }

  // 4. Hostname patterns
  try {
    const host = hostname().toLowerCase();
    if (host.startsWith("prod-") || host.startsWith("prod.")) {
      return Environment.PRODUCTION;
    }
    if (
      host.startsWith("stg-") ||
      host.startsWith("stg.") ||
      host.startsWith("staging-") ||
      host.startsWith("staging.")
    ) {
      return Environment.STAGING;
    }
  } catch {
    // hostname not available
  }

  // 5. Default
  return Environment.DEVELOPMENT;
}
