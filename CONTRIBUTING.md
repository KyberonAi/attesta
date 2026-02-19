# Contributing

## Prerequisites

- Python 3.11+ (3.12 recommended)
- Node.js 20+
- `npm` and `pip`

## Local Setup

```bash
git clone https://github.com/KyberonAi/attesta.git
cd attesta
python -m pip install --upgrade pip
pip install -e "./python[dev,yaml]"
npm ci
```

## Test Matrix

Run before opening a PR:

```bash
PYTHONPATH=python/src pytest -q
```

```bash
npm run --workspace @kyberon/attesta typecheck
npm run --workspace @kyberon/attesta build
npm run --workspace @kyberon/attesta test
```

```bash
PYTHONPATH=python/src pytest -q packages/langflow-attesta/tests
PYTHONPATH=python/src pytest -q packages/dify-attesta/tests
```

```bash
./scripts/check_release_boundary.sh
```

## Pull Request Guidelines

- Keep changes focused and include tests for behavior changes.
- Update docs when public behavior changes.
- Avoid introducing breaking API changes in patch releases.
- Include migration notes for any changed defaults or security posture.
- Use the PR checklist in `.github/pull_request_template.md`.

## Commit Guidelines

- Use clear, imperative commit messages.
- Reference issue IDs when available.

## Community Process

- File bugs/features/docs requests using templates under `.github/ISSUE_TEMPLATE/`.
- Review `SUPPORT.md` for response expectations.
- Security issues must be reported privately per `SECURITY.md`.
