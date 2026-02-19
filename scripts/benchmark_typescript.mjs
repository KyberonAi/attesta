#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const sdkPath = path.join(repoRoot, "typescript", "dist", "esm", "index.js");

let sdk;
try {
  sdk = await import(sdkPath);
} catch (err) {
  console.error("TypeScript dist build not found. Run npm build first.");
  throw err;
}

const {
  Attesta,
  RiskLevel,
  Verdict,
  createActionContext,
} = sdk;

class FastApproveRenderer {
  async renderApproval() {
    return Verdict.APPROVED;
  }

  async renderChallenge(_ctx, _risk, challengeType) {
    return {
      passed: true,
      challengeType,
      responder: "bench",
      responseTimeSeconds: 0,
      questionsAsked: 0,
      questionsCorrect: 0,
      details: {},
    };
  }

  async renderInfo() {}
  async renderAutoApproved() {}
}

class SilentAuditLogger {
  async log() {
    return "bench";
  }
}

function summarize(samplesMs) {
  if (samplesMs.length === 0) {
    return { p50_ms: 0, p95_ms: 0, mean_ms: 0 };
  }
  const sorted = [...samplesMs].sort((a, b) => a - b);
  const p50 = sorted[Math.floor(0.5 * (sorted.length - 1))];
  const p95 = sorted[Math.floor(0.95 * (sorted.length - 1))];
  const mean = sorted.reduce((a, b) => a + b, 0) / sorted.length;
  return {
    p50_ms: Number(p50.toFixed(6)),
    p95_ms: Number(p95.toFixed(6)),
    mean_ms: Number(mean.toFixed(6)),
  };
}

async function measureCase(gate, ctx, iterations, warmup) {
  for (let i = 0; i < warmup; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await gate.evaluate(ctx);
  }

  const samplesMs = [];
  for (let i = 0; i < iterations; i += 1) {
    const start = performance.now();
    // eslint-disable-next-line no-await-in-loop
    await gate.evaluate(ctx);
    samplesMs.push(performance.now() - start);
  }
  return summarize(samplesMs);
}

function parseArgs() {
  const args = {
    iterations: 500,
    warmup: 50,
    output: null,
  };
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--iterations") args.iterations = Number(argv[++i]);
    if (arg === "--warmup") args.warmup = Number(argv[++i]);
    if (arg === "--output") args.output = argv[++i];
  }
  return args;
}

const { iterations, warmup, output } = parseArgs();
const renderer = new FastApproveRenderer();

const lowGate = new Attesta({
  renderer,
  auditLogger: new SilentAuditLogger(),
  riskOverride: RiskLevel.LOW,
});
const highGate = new Attesta({
  renderer,
  auditLogger: new SilentAuditLogger(),
  riskOverride: RiskLevel.HIGH,
});

const lowCtx = createActionContext({ functionName: "listUsers" });
const highCtx = createActionContext({
  functionName: "deleteProductionRecords",
  kwargs: { table: "users" },
  hints: { destructive: true, pii: true },
  environment: "production",
});

const report = {
  benchmark: "attesta-typescript",
  iterations,
  warmup,
  cases: {
    low_risk_auto_approve: await measureCase(lowGate, lowCtx, iterations, warmup),
    high_risk_challenge_pass: await measureCase(highGate, highCtx, iterations, warmup),
  },
};

const reportJson = JSON.stringify(report, null, 2);
if (output) {
  const outPath = path.resolve(repoRoot, output);
  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${reportJson}\n`, "utf8");
  console.log(`Wrote benchmark report: ${outPath}`);
} else {
  console.log(reportJson);
}
