---
description: Generate an implementation plan from an approved spec
argument-hint: Feature slug (e.g., "trailproof-integration")
allowed-tools: Read, Write, Glob
---

You are creating an implementation plan for an Attesta feature.

User input: $ARGUMENTS

## Step 1. Read the spec

Read .claude/specs/$ARGUMENTS.md.

If the file doesn't exist, stop and say:
"No spec found at .claude/specs/$ARGUMENTS.md. Run /spec first."

If the Status field is not "Approved", stop and say:
"Spec must be approved before planning. Review .claude/specs/$ARGUMENTS.md and change Status to Approved first."

## Step 2. Read context

Read:
- CLAUDE.md (workflow rules, build order)
- python/CLAUDE.md (Python conventions)
- typescript/CLAUDE.md (TypeScript conventions)

## Step 3. Create the plan

Read the template at .claude/templates/plan.md.
Create .claude/plans/$ARGUMENTS.md using that template structure.

Fill in the tasks based on the spec:
- Each task is one commit's worth of work
- Each task includes: scope (`python` | `typescript` | `both`), complexity (`small` | `medium` | `large`)
- Python tasks first, TypeScript mirror tasks after, shared test vectors last
- Call out dependencies between tasks
- Do NOT write any implementation code

## Step 4. Final output

Respond with:

```
Plan file: .claude/plans/$ARGUMENTS.md
Tasks: <count> total (<python_count> Python, <ts_count> TypeScript, <shared_count> shared)
```

Then: "Plan ready for review. Approve or provide changes."

Do NOT print the full plan in chat unless the user asks.
