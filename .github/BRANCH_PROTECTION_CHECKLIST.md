# Branch Protection Checklist (`main`)

Use this checklist before opening the public launch window.

## 1. Core Protection Rules

- [ ] Require a pull request before merging.
- [ ] Require at least 1 approving review (2 recommended for release week).
- [ ] Require review from Code Owners.
- [ ] Dismiss stale reviews when new commits are pushed.
- [ ] Require conversation resolution before merge.
- [ ] Restrict direct pushes to `main`.
- [ ] Restrict force-pushes and branch deletion.

## 2. Required Status Checks

Mark these checks as required in branch protection:

- [ ] `Dependency Review`
- [ ] `OSS Boundary`
- [ ] `Python Tests + Build`
- [ ] `No-Code Python Package Tests`
- [ ] `TypeScript Build + Pack`
- [ ] `Docs Links`
- [ ] `CodeQL`
- [ ] `Secrets Scan (Gitleaks)`
- [ ] `Dependency Vulnerability Scan`
- [ ] `Semgrep SAST`
- [ ] `SBOM + Provenance`

## 3. Admin/Bypass Policy

- [ ] Include administrators in protection.
- [ ] Disable bypass for all non-release-maintainer roles.
- [ ] Ensure emergency bypass requires post-incident writeup in `MAINTAINERS.md`.

## 4. Release-Week Extras (Recommended)

- [ ] Enable required linear history.
- [ ] Require successful deployment checks for docs/prod environments if configured.
- [ ] Require signed commits for release branches/tags.

## 5. Verification

- [ ] Open a test PR and confirm each required check blocks merge when failing.
- [ ] Confirm merge is blocked without Code Owner review.
- [ ] Confirm direct push to `main` is denied for non-admin users.
