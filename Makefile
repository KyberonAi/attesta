.PHONY: all python typescript test lint typecheck clean install docs \
       test-python test-typescript lint-python lint-typescript \
       typecheck-python typecheck-typescript build-python build-typescript \
       test-nocode

# ── Aggregate ────────────────────────────────────────────────────────

all: python typescript

install:
	cd python && pip install -e ".[dev,yaml,terminal]"
	cd typescript && npm install

# ── Python SDK ───────────────────────────────────────────────────────

python: lint-python typecheck-python test-python

build-python:
	cd python && pip install -e ".[dev,yaml,terminal]"

test-python:
	PYTHONPATH=python/src python -m pytest python/tests/ -q

lint-python:
	cd python && ruff check src tests

typecheck-python:
	cd python && mypy src/attesta

# ── TypeScript SDK ───────────────────────────────────────────────────

typescript: lint-typescript typecheck-typescript build-typescript test-typescript

build-typescript:
	cd typescript && npm run build

test-typescript:
	cd typescript && npm test

lint-typescript:
	cd typescript && npx tsc --noEmit

typecheck-typescript:
	cd typescript && npx tsc --noEmit

# ── No-code packages ────────────────────────────────────────────────

test-nocode:
	PYTHONPATH=python/src pytest packages/n8n-nodes-attesta/tests -q 2>/dev/null || true
	PYTHONPATH=python/src pytest packages/flowise-attesta/tests -q 2>/dev/null || true

# ── Combined ─────────────────────────────────────────────────────────

test: test-python test-typescript test-nocode

lint: lint-python lint-typescript

typecheck: typecheck-python typecheck-typescript

# ── Docs ─────────────────────────────────────────────────────────────

docs:
	cd docs && npx mintlify dev

# ── Clean ────────────────────────────────────────────────────────────

clean:
	cd python && rm -rf dist build *.egg-info src/*.egg-info
	cd typescript && npm run clean
