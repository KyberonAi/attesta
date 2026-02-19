# GitHub Actions Setup

Configure these GitHub Secrets before enabling publish/review workflows:

- `MINTLIFY_DEPLOY_HOOK_URL`: optional webhook URL for Mintlify deploy trigger
- `OPENAI_API_KEY`: optional, used by AI review workflow (Codex/OpenAI)
- `ANTHROPIC_API_KEY`: optional, used by AI review workflow (Claude/Anthropic)

Optional repository variables:

- `OPENAI_REVIEW_MODEL` (default: `gpt-4o-mini`)
- `ANTHROPIC_REVIEW_MODEL` (default: `claude-3-5-sonnet-latest`)

Recommended GitHub Environments:

- `pypi`
- `npm`
- `docs-prod`

PyPI Trusted Publishing (recommended, no API token):

1. In PyPI, open your `attesta` project settings.
2. Add a new Trusted Publisher with:
   - Owner: your GitHub org/user
   - Repository name: `attesta`
   - Workflow name: `release.yaml`
   - Environment name: `pypi`
3. In GitHub, create the `pypi` Environment in the repo and keep or add your protection rules.
4. Do not set `PYPI_API_TOKEN`; `release.yaml` publishes using OIDC (`id-token: write`) via `pypa/gh-action-pypi-publish`.

Important:

- The workflow filename must exactly match `.github/workflows/release.yaml`.
- If you rename the workflow or environment, update the PyPI Trusted Publisher entry.
- PyPI Trusted Publishing does not support reusable workflows for publisher identity.

npm Trusted Publishing (recommended, no automation token):

1. In npm, open package settings for `@kyberon/attesta`.
2. Add a new Trusted Publisher with:
   - GitHub owner: your org/user
   - Repository name: `attesta`
   - Workflow filename: `release.yaml`
   - Environment name: `npm`
3. In GitHub, create the `npm` Environment in the repo and keep or add protection rules.
4. Do not set `NPM_TOKEN` for publishing; `release.yaml` publishes via OIDC (`id-token: write`) with `npm publish --provenance`.

Important:

- Trusted publishing applies only to GitHub-hosted runners.
- Keep npm CLI current in the workflow for trusted publishing compatibility.

Recommended required status checks on `main` branch protection:

- `Dependency Review`
- `OSS Boundary`
- `Python Tests + Build`
- `TypeScript Build + Pack`
- `Docs Links`
- `CodeQL`
- `Secrets Scan (Gitleaks)`
- `Dependency Vulnerability Scan`
- `Semgrep SAST`
- `SBOM + Provenance`

AI review is intentionally advisory and label-gated (`ai-review`).

Release notes:

- Release workflow publishes on `vX.Y.Z` tags (or manual run with version input).
- It validates Python/npm version match, builds artifacts in `verify`, publishes to PyPI (OIDC) and npm (OIDC), runs smoke tests from PyPI/npm with retry, then creates a GitHub Release with checksums/artifacts attached.
