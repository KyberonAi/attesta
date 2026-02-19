# LangChain Tool Approval Example

This example wraps a LangChain tool list with Attesta so destructive operations require explicit human verification.

## Install

```bash
pip install "attesta[langchain,yaml,terminal]"
```

## Run

```bash
cd examples/langchain-tooling-approval
python tool.py
```

## What it demonstrates

- `AttestaToolWrapper` for tool-level gating
- per-tool risk overrides for dangerous operations
- consistent audit trail for LangChain tool invocations
