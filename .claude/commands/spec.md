---
description: Create a feature spec file and branch from a short idea
argument-hint: Short feature description (e.g., "trailproof integration" or "custom renderer")
allowed-tools: Read, Write, Glob, Bash(git switch:*), Bash(git branch:*), Bash(git status)
---

You are creating a new feature spec for the Attesta project from the user input below.
Always adhere to CLAUDE.md rules.

User input: $ARGUMENTS

## Step 1. Check the current branch

Run `git status`. If there are uncommitted, unstaged, or untracked files (excluding files in .gitignore), abort and tell the user to commit or stash first. DO NOT proceed.

## Step 2. Parse the arguments

From `$ARGUMENTS`, extract:

1. `feature_title` — short human-readable title in Title Case (e.g., "TrailProof Integration")
2. `feature_slug` — kebab-case, lowercase, a-z/0-9/hyphens only, max 40 chars (e.g., "trailproof-integration")
3. `branch_name` — format: `feature/<feature_slug>`

If you cannot infer a sensible title and slug, ask the user to clarify.

## Step 3. Switch to a new Git branch

Create and switch to `branch_name`. If already taken, append a number (e.g., `feature/trailproof-integration-01`).

## Step 4. Read context

Read:
- CLAUDE.md (project conventions)
- All existing specs in .claude/specs/ (avoid overlap)

## Step 5. Draft the spec

Read the template at .claude/templates/spec.md.
Create .claude/specs/<feature_slug>.md using that template structure.

Fill in all sections based on the user input and project context:
- Show Python AND TypeScript API signatures side by side
- Acceptance criteria must be testable
- Testing guidelines should list specific test scenarios
- Do NOT write implementation code or technical details like file paths

## Step 6. Final output

After saving, respond with:

```
Branch: <branch_name>
Spec file: .claude/specs/<feature_slug>.md
Title: <feature_title>
```

Then: "Spec ready for review. Approve or provide changes."

Do NOT print the full spec in chat unless the user asks.
