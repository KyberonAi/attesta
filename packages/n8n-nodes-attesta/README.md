# n8n-nodes-attesta

n8n community node for [Attesta](https://attesta.dev) human-in-the-loop approval gates.

Attesta provides a lightweight approval framework for AI agent actions. This node lets you insert approval gates into n8n workflows so that high-risk actions can be reviewed before execution.

## Installation

1. Open your n8n instance.
2. Go to **Settings > Community Nodes**.
3. Enter `n8n-nodes-attesta` and click **Install**.

For self-hosted n8n you can also install via the CLI:

```bash
npm install n8n-nodes-attesta
```

## Configuration

### Credentials: Attesta

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| Risk Threshold | number | 0.5 | Default risk threshold (0-1). Actions scoring above this are flagged for review. |

### Node: Attesta Approval

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| Function Name | string | (required) | Name of the action being gated (e.g. `send_email`, `delete_record`). |
| Risk Level | options | Auto | Risk level override. **Auto** uses the built-in risk scorer. Other options: Low, Medium, High, Critical. |
| Risk Hints | JSON | `{}` | JSON object of risk hints passed to the scorer (e.g. `{"destructive": true, "pii": true}`). |
| On Denied | options | Error | What happens when the action is denied. **Error** stops the workflow. **Passthrough** attaches denial metadata and continues. |

## How It Works

1. The node receives input items from the previous step in the workflow.
2. For each item, it creates an Attesta action context using the configured function name and the item data as keyword arguments.
3. The Attesta Approval evaluates the action, computing a risk score and determining whether the action should be approved or denied.
4. Based on the verdict:
   - **Approved / Modified**: The item passes through with `_attesta` metadata attached (verdict, risk score, risk level, audit entry ID).
   - **Denied / Timed Out / Escalated**: Depending on the **On Denied** setting, the workflow either throws an error or passes the item through with denial metadata.

### Output Metadata

Every output item includes an `_attesta` object:

```json
{
  "_attesta": {
    "verdict": "approved",
    "riskScore": 0.2,
    "riskLevel": "low",
    "auditEntryId": "audit-abc123",
    "denied": false
  }
}
```

## Development

```bash
npm install
npm run build
npm test
```

## License

Apache 2.0

## Links

- [Attesta Documentation](https://attesta.dev)
- [n8n Community Nodes Documentation](https://docs.n8n.io/integrations/community-nodes/)
