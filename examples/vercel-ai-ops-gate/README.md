# Vercel AI Middleware Example

This example wires Attesta middleware into Vercel AI SDK tool execution.

## Install

```bash
npm install @kyberon/attesta ai
```

## Run

Compile or run in your existing TypeScript application and import `index.ts`.

## What it demonstrates

- middleware-based approval enforcement
- timeout and fail-mode policy (`escalate`) for high-impact actions
- single policy surface for multi-tool operations routes
