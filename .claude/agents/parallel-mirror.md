---
name: parallel-mirror
description: Mirror a completed Python module to TypeScript. Use after Python implementation is done and tested.
tools: Read, Glob, Grep, Bash, Write, Edit
model: sonnet
---

The Python implementation of $ARGUMENTS is complete. Mirror it to TypeScript.

1. If the file .claude/skills/dual-sdk-parity.md exists, read it first.
2. Read typescript/CLAUDE.md for TypeScript conventions.
3. Read the Python source in python/src/attesta/ for the $ARGUMENTS module.
4. Implement the TypeScript mirror in typescript/src/ following these parity rules:
   - Same public API (snake_case fields on wire types, camelCase methods)
   - Same behavior and edge case handling
   - Same error types
   - Must pass shared test vectors in fixtures/
5. Run `cd typescript && npm run typecheck && npm run build && npm test`.
6. Report:
   - What was implemented
   - Any parity issues found
   - Type translation decisions made (e.g., Python dict -> TypeScript Record)
   - Test results

Do not touch Python files. Do not modify package.json without reporting it.
