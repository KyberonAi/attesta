.PHONY: all python typescript test lint typecheck clean install docs \
       test-python test-typescript lint-python lint-typescript \
       typecheck-python typecheck-typescript build-python build-typescript \
       test-nocode

# ── Aggregate ────────────────────────────────────────────────────────

all: python typescript

install:
	cd python && uv sync --all-extras
	cd typescript && npm install

# ── Python SDK ───────────────────────────────────────────────────────

python:
	$(MAKE) -C python all

build-python:
	cd python && uv sync --all-extras

test-python:
	$(MAKE) -C python test

lint-python:
	$(MAKE) -C python lint

typecheck-python:
	$(MAKE) -C python typecheck

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
	cd python && uv run pytest ../packages/n8n-nodes-attesta/tests -q 2>/dev/null || true
	cd python && uv run pytest ../packages/flowise-attesta/tests -q 2>/dev/null || true

# ── Combined ─────────────────────────────────────────────────────────

test: test-python test-typescript test-nocode

lint: lint-python lint-typescript

typecheck: typecheck-python typecheck-typescript

# ── Docs ─────────────────────────────────────────────────────────────

docs:
	cd docs && npx mintlify dev

# ── Clean ────────────────────────────────────────────────────────────

clean:
	cd python && rm -rf dist build *.egg-info src/*.egg-info .venv
	cd typescript && npm run clean
