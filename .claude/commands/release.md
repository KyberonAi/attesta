---
description: Prepare a release by bumping versions and creating a tag
argument-hint: <version> (e.g., 1.2.0)
allowed-tools: Bash(git status), Bash(git diff *), Bash(git add *), Bash(git commit *), Bash(git log *), Bash(git branch *), Bash(git tag *), Bash(git rev-parse *), Bash(cat *), Bash(python *), Bash(node *), Bash(npm *), Bash(jq *), Read, Edit, Glob, Grep
---

Prepare a release. This command does NOT push or publish -- the user handles that.

## Step 0. Validate

If no version argument is provided, stop and ask the user for a version number.

The version must follow semver (e.g., `1.2.0`). Do NOT accept pre-release tags unless explicitly asked.

Run `git status` to ensure the working tree is clean. If there are uncommitted changes, tell the user to commit first.

## Step 1. Determine current version

Read `python/pyproject.toml` and find the current `version = "..."` line.
Read `typescript/package.json` and find the current `"version": "..."` field.
Report both current versions.

If they differ, warn the user and ask which to use as the baseline.

## Step 2. Bump versions

Update the version in:
- `python/pyproject.toml` (the `version = "..."` line)
- `typescript/package.json` (the `"version": "..."` field)

Show the diff and ask for user confirmation.

## Step 3. Update changelog (if exists)

Check if a `CHANGELOG.md` exists. If so:
- Run `git log --oneline` from the last tag to HEAD
- Draft a changelog section for the new version
- Show it and ask the user to approve or edit

If no CHANGELOG.md, skip this step.

## Step 4. Commit version bump

Stage the changed files and commit with:
```
chore: bump version to {version}
```

Ask user to confirm before committing.

## Step 5. Create tag

Tell the user what tag will be created: `v{version}`

Ask for confirmation. After approval, create the tag:
```
git tag v{version}
```

## Step 6. Done

Report what was done:
- Version bumped in: (list files)
- Commit: (hash)
- Tag: v{version}

Tell the user:
```
Release prepared. To publish:
  git push origin main --tags
```

Rules:
- Do NOT push to remote
- Do NOT publish to any registry
- Do NOT run the tag command without explicit user approval
- Do NOT modify files outside of version/changelog
