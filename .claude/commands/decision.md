---
description: Create an Architecture Decision Record (ADR)
argument-hint: Decision topic in kebab-case (e.g., "trailproof-audit-backend")
allowed-tools: Read, Write, Glob
---

You are creating an ADR for the Attesta project.

User input: $ARGUMENTS

## Step 1. Determine next ADR number

Check existing files in .claude/decisions/ to find the highest ADR number. Increment by 1.
If no ADRs exist, start at 1.

## Step 2. Create the ADR

Create .claude/decisions/ADR-<next_number>-$ARGUMENTS.md with:

```markdown
# ADR-<number>: <Decision Title>

## Status
Proposed

## Context
What situation forced this decision.

## Options Considered

### Option A: <name>
Description. Pros. Cons.

### Option B: <name>
Description. Pros. Cons.

## Decision
What we chose and why.

## Consequences

### Good
- Honest benefits

### Bad
- Honest downsides
```

Rules:
- Minimum 2 options considered
- Be honest about consequences -- include real downsides
- Explain WHY, not just WHAT
- Do NOT implement anything
