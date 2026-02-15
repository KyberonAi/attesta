# dify-attesta

Dify plugin for [Attesta](https://attesta.dev) human-in-the-loop approval gates. This plugin adds an **Attesta Approval** tool to Dify that evaluates AI agent actions for risk and enforces approval policies before execution.

## Installation

1. Build the `.difypkg` archive from this directory.
2. In the Dify dashboard, navigate to **Plugins** and upload the `.difypkg` file.

## Configuration

### Provider Credentials

| Credential       | Type   | Required | Default | Description                                                   |
|-------------------|--------|----------|---------|---------------------------------------------------------------|
| `risk_threshold`  | number | No       | `0.5`   | Default risk threshold (0--1). Actions scoring above this are flagged for review. |

### Tool Parameters

| Parameter       | Type   | Required | Form | Description                                                      |
|-----------------|--------|----------|------|------------------------------------------------------------------|
| `function_name` | string | Yes      | LLM  | Name of the action being evaluated (e.g. `send_email`).         |
| `risk_level`    | select | No       | Form | Override the risk level: `auto`, `low`, `medium`, `high`, `critical`. |
| `action_args`   | string | No       | LLM  | JSON string of arguments for the action being evaluated.        |

## How It Works

1. The LLM (or a preceding workflow step) calls the **Attesta Approval** tool with the `function_name` and optional `action_args`.
2. The tool constructs an `ActionContext` and passes it to `Attesta.evaluate()`.
3. Attesta scores the action for risk, applies the configured threshold, and returns an `ApprovalResult`.
4. The tool yields a JSON message containing:
   - `verdict` -- one of `approved`, `denied`, `modified`, `timed_out`, `escalated`
   - `risk_score` -- numeric score between 0 and 1
   - `risk_level` -- `low`, `medium`, `high`, or `critical`
   - `denied` -- boolean shorthand
   - `audit_entry_id` -- for traceability
   - `message` -- human-readable summary

Downstream nodes can branch on the `denied` field to decide whether to proceed with the action.

## Development

```bash
# Run tests
pytest tests/
```

## Links

- Attesta documentation: [https://attesta.dev](https://attesta.dev)
