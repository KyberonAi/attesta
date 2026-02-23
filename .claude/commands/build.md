---
description: Implement the next unchecked task from a plan
argument-hint: Feature slug (e.g., "trailproof-integration")
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(make *), Bash(npm run *), Bash(uv *), Bash(git add *), Bash(git commit *), Bash(git status), Bash(git diff *)
---

You are implementing one task from the Attesta build plan.

User input: $ARGUMENTS

## Step 1. Read the plan

Read .claude/plans/$ARGUMENTS.md.

If the file doesn't exist, stop and say:
"No plan found at .claude/plans/$ARGUMENTS.md. Run /plan first."

Identify the FIRST unchecked task (`- [ ]`).

If all tasks are checked, stop and say:
"All tasks complete. Run /review $ARGUMENTS to check acceptance criteria."

## Step 2. Read context

Before implementing, read:
- If task scope is `python`: read python/CLAUDE.md
- If task scope is `typescript`: read typescript/CLAUDE.md
- If task scope is `both`: read both
- Read .claude/specs/$ARGUMENTS.md for reference
- If any skills exist in .claude/skills/ relevant to this task, read them

## Step 3. Implement the single task

Write the code for this one task only.

## Step 4. Run checks

1. If Python: run `.venv/bin/python -m pytest python/tests/ -q` and `cd python && ruff check src tests`. Fix any lint, type, or test failures.
2. If TypeScript: run `cd typescript && npm run typecheck && npm run build && npm test`. Fix any lint, type, or test failures.
3. If both: run both.

Do NOT move on until all checks pass.

## Step 5. Update the plan

Check off the completed task in .claude/plans/$ARGUMENTS.md (change `- [ ]` to `- [x]`).

## Step 6. Commit

You MUST invoke the /commit skill using the Skill tool -- do NOT run git add/commit commands directly. The /commit skill handles staging, message drafting, and user approval. Never bypass it.

## Step 7. Report

Stop and report:
- **Done:** what was implemented
- **Tests:** pass/fail summary
- **Next:** the next unchecked task (or "all done")

Rules:
- Do NOT continue to the next task automatically
- Do NOT skip failing tests -- fix them before committing
- One task = one commit
