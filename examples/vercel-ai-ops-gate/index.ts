import { createAttestaMiddleware } from "@kyberon/attesta/integrations";

export const attestaMiddleware = createAttestaMiddleware({
  failMode: "escalate",
  approvalTimeoutSeconds: 45,
  riskHints: {
    production: true,
    external_side_effect: true,
  },
});

// Attach `attestaMiddleware` to your Vercel AI SDK request pipeline.
// Any blocked or escalated verdict should be treated as non-executable.
