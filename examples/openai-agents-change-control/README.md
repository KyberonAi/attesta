# OpenAI Agents Change-Control Example

This example shows how to block or escalate dangerous database change tools before execution.

## Install

```bash
pip install "attesta[openai,yaml,terminal]"
```

## Run

```bash
cd examples/openai-agents-change-control
python app.py
```

## What it demonstrates

- `fail_mode: escalate` timeout behavior for high-risk actions
- approval contract through `attesta_approval_handler`
- explicit metadata (`change_ticket`, `environment`) for audit traceability
