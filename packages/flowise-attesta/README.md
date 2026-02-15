# flowise-nodes-attesta

Flowise community node for [Attesta](https://attesta.dev) human-in-the-loop approval gates. Add safety guardrails to your Flowise AI agent workflows by requiring human approval before high-risk actions execute.

## Installation

Copy this package into your Flowise custom components directory:

```bash
# From your Flowise installation
cp -r flowise-nodes-attesta /path/to/flowise/packages/components/nodes/AttestaGate
```

Or install as a dependency in your custom Flowise components project:

```bash
npm install flowise-nodes-attesta
```

## Configuration

The Attesta Approval node exposes the following properties in the Flowise canvas:

| Property | Type | Default | Description |
|---|---|---|---|
| **Function Name** | string | `gated_action` | Name of the action being gated (e.g. `send_email`, `delete_record`) |
| **Risk Level** | options | `auto` | Risk level override. Options: Auto (score-based), Low, Medium, High, Critical |
| **Risk Hints** | JSON | `{}` | JSON object of risk hints (e.g. `{"destructive": true, "pii": true}`) |
| **Tool Description** | string | `A gated action that requires approval before execution` | Description shown to the LLM for this tool |

## How It Works

1. Drag the **Attesta Approval** node onto your Flowise canvas and connect it as a Tool input to an Agent node.
2. Configure the function name and risk level for the action you want to evaluate.
3. When the agent invokes the tool, Attesta evaluates the action context against configured policies and risk thresholds.
4. If the action is **approved**, the tool returns a success JSON payload with the verdict, risk score, and audit entry ID.
5. If the action is **denied**, **timed out**, or **escalated**, the tool returns a denial JSON payload with the reason.

The agent receives the result and can decide how to proceed based on the approval status.

### Example Response (Approved)

```json
{
  "status": "approved",
  "verdict": "approved",
  "riskScore": 0.1,
  "riskLevel": "low",
  "auditEntryId": "audit-abc123",
  "input": { "to": "user@example.com" }
}
```

### Example Response (Denied)

```json
{
  "status": "denied",
  "verdict": "denied",
  "riskScore": 0.9,
  "riskLevel": "critical",
  "message": "Action \"send_email\" was denied by Attesta (risk: critical)"
}
```

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT

## Links

- [Attesta Documentation](https://attesta.dev)
- [Flowise](https://flowiseai.com)
