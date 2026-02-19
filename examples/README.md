# Attesta Example Apps

These examples are production-style starting points for common approval workflows.

## Included examples

- `openai-agents-change-control/`: gate high-impact tool calls before OpenAI agent execution.
- `langchain-tooling-approval/`: wrap LangChain tools with risk-based human approval.
- `vercel-ai-ops-gate/`: apply Attesta middleware to Vercel AI SDK tool calls.

## Run conventions

- Python examples use `attesta.yaml` in the example folder.
- TypeScript examples assume `@kyberon/attesta` and peer framework packages are installed.
- These are integration skeletons meant to be adapted to your auth, audit storage, and routing stack.
