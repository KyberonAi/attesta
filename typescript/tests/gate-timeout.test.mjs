import assert from "node:assert/strict";
import test from "node:test";

import {
  Attesta,
  DefaultRiskScorer,
  EventBus,
  EventType,
  RiskLevel,
  Verdict,
  createActionContext,
} from "../dist/esm/index.js";

class SlowRenderer {
  async renderApproval() {
    return Verdict.APPROVED;
  }

  async renderChallenge(_ctx, _risk, challengeType) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    return {
      passed: true,
      challengeType,
      responder: "test",
      responseTimeSeconds: 0,
      questionsAsked: 0,
      questionsCorrect: 0,
      details: {},
    };
  }

  async renderInfo() {}

  async renderAutoApproved() {}
}

class ApproveRenderer {
  async renderApproval() {
    return Verdict.APPROVED;
  }

  async renderChallenge(_ctx, _risk, challengeType) {
    return {
      passed: true,
      challengeType,
      responder: "test",
      responseTimeSeconds: 0,
      questionsAsked: 0,
      questionsCorrect: 0,
      details: {},
    };
  }

  async renderInfo() {}

  async renderAutoApproved() {}
}

test("timeout with failMode=deny returns timed_out", async () => {
  const gate = new Attesta({
    renderer: new SlowRenderer(),
    riskOverride: RiskLevel.HIGH,
    approvalTimeoutSeconds: 0.05,
    failMode: "deny",
  });
  const ctx = createActionContext({ functionName: "delete_data" });
  const result = await gate.evaluate(ctx);

  assert.equal(result.verdict, Verdict.TIMED_OUT);
  assert.equal(result.metadata.failMode, "deny");
  assert.equal(result.metadata.timedOut, true);
});

test("timeout with failMode=allow returns approved", async () => {
  const gate = new Attesta({
    renderer: new SlowRenderer(),
    riskOverride: RiskLevel.HIGH,
    approvalTimeoutSeconds: 0.05,
    failMode: "allow",
  });
  const ctx = createActionContext({ functionName: "delete_data" });
  const result = await gate.evaluate(ctx);

  assert.equal(result.verdict, Verdict.APPROVED);
  assert.equal(result.metadata.failMode, "allow");
  assert.equal(result.metadata.timedOut, true);
});

test("timeout with failMode=escalate returns escalated and emits event", async () => {
  const events = [];
  const eventBus = new EventBus();
  eventBus.on(EventType.ESCALATED, (event) => events.push(event));

  const gate = new Attesta({
    renderer: new SlowRenderer(),
    riskOverride: RiskLevel.HIGH,
    approvalTimeoutSeconds: 0.05,
    failMode: "escalate",
    eventBus,
  });
  const ctx = createActionContext({ functionName: "delete_data" });
  const result = await gate.evaluate(ctx);

  assert.equal(result.verdict, Verdict.ESCALATED);
  assert.equal(events.length, 1);
  assert.equal(events[0].data.verdict, Verdict.ESCALATED);
});

test("default gate scorer matches DefaultRiskScorer and returns factor breakdown", async () => {
  const ctx = createActionContext({
    functionName: "delete_production_database",
    args: ["users"],
    functionDoc: "Dangerous irreversible operation.",
    hints: { destructive: true, pii: true },
    environment: "production",
  });

  const gate = new Attesta({
    renderer: new ApproveRenderer(),
  });
  const expectedScore = new DefaultRiskScorer().score(ctx);
  const result = await gate.evaluate(ctx);

  assert.equal(result.riskAssessment.score, expectedScore);
  assert.equal(result.riskAssessment.scorerName, "default");
  assert.equal(result.riskAssessment.factors.length >= 5, true);
  assert.equal(
    result.riskAssessment.factors.some((f) => f.name === "function_name"),
    true
  );
});
