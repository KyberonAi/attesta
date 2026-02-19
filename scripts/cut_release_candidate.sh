#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/cut_release_candidate.sh --version X.Y.Z --pre LABEL --num N [--push] [--skip-checks] [--allow-dirty]

Examples:
  ./scripts/cut_release_candidate.sh --version 0.2.0 --pre beta --num 1
  ./scripts/cut_release_candidate.sh --version 0.2.0 --pre rc --num 1 --push

Options:
  --version       Release version without leading "v" (example: 0.2.0)
  --pre           Pre-release label (example: beta, rc)
  --num           Pre-release sequence number (example: 1 -> v0.2.0-beta.1)
  --push          Push created tag to origin
  --skip-checks   Skip preflight checks (not recommended)
  --allow-dirty   Allow running with local uncommitted changes
  -h, --help      Show this help text
USAGE
}

VERSION=""
PRE_LABEL=""
PRE_NUM=""
DO_PUSH=0
SKIP_CHECKS=0
ALLOW_DIRTY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --pre)
      PRE_LABEL="${2:-}"
      shift 2
      ;;
    --num)
      PRE_NUM="${2:-}"
      shift 2
      ;;
    --push)
      DO_PUSH=1
      shift
      ;;
    --skip-checks)
      SKIP_CHECKS=1
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${VERSION}" || -z "${PRE_LABEL}" || -z "${PRE_NUM}" ]]; then
  usage
  exit 1
fi

if ! [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid --version '${VERSION}'. Expected X.Y.Z." >&2
  exit 1
fi

if ! [[ "${PRE_LABEL}" =~ ^[a-z0-9-]+$ ]]; then
  echo "Invalid --pre '${PRE_LABEL}'. Use lowercase letters, numbers, or dashes." >&2
  exit 1
fi

if ! [[ "${PRE_NUM}" =~ ^[0-9]+$ ]] || (( PRE_NUM < 1 )); then
  echo "Invalid --num '${PRE_NUM}'. Expected integer >= 1." >&2
  exit 1
fi

TAG="v${VERSION}-${PRE_LABEL}.${PRE_NUM}"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
REPORT_PATH="artifacts/release/${TAG}.md"

choose_python() {
  for candidate in python3.12 python3.11 python3; do
    if ! command -v "${candidate}" >/dev/null 2>&1; then
      continue
    fi
    if "${candidate}" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
    then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}

run_step() {
  local label="$1"
  shift
  echo "[release] ${label}"
  "$@"
}

PYTHON_BIN="$(choose_python || true)"
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "Python 3.11+ is required." >&2
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${CURRENT_BRANCH}" != "main" ]]; then
  echo "Current branch is '${CURRENT_BRANCH}'. Cut release tags from 'main'." >&2
  exit 1
fi

if [[ "${ALLOW_DIRTY}" -ne 1 ]]; then
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "Working tree is not clean. Commit/stash or use --allow-dirty." >&2
    exit 1
  fi
fi

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "Tag already exists locally: ${TAG}" >&2
  exit 1
fi

if git remote get-url origin >/dev/null 2>&1; then
  if git ls-remote --tags origin "refs/tags/${TAG}" | rg -q .; then
    echo "Tag already exists on origin: ${TAG}" >&2
    exit 1
  fi
else
  echo "[release] Warning: no 'origin' remote configured; skipping remote tag check."
fi

PY_VERSION="$(${PYTHON_BIN} - <<'PY'
import tomllib
from pathlib import Path
data = tomllib.loads(Path('python/pyproject.toml').read_text())
print(data['project']['version'])
PY
)"
TS_VERSION="$(node -p "require('./typescript/package.json').version")"

if [[ "${PY_VERSION}" != "${VERSION}" ]]; then
  echo "Python version mismatch: pyproject=${PY_VERSION}, requested=${VERSION}" >&2
  exit 1
fi
if [[ "${TS_VERSION}" != "${VERSION}" ]]; then
  echo "TypeScript version mismatch: package=${TS_VERSION}, requested=${VERSION}" >&2
  exit 1
fi

CHECKS_RAN=()
if [[ "${SKIP_CHECKS}" -ne 1 ]]; then
  run_step "Boundary check" ./scripts/check_release_boundary.sh
  CHECKS_RAN+=("./scripts/check_release_boundary.sh")

  run_step "Python tests" env PYTHONPATH=python/src "${PYTHON_BIN}" -m pytest -q python/tests
  CHECKS_RAN+=("PYTHONPATH=python/src ${PYTHON_BIN} -m pytest -q python/tests")

  run_step "TypeScript typecheck" npm run --workspace @kyberon/attesta typecheck
  CHECKS_RAN+=("npm run --workspace @kyberon/attesta typecheck")

  run_step "TypeScript build" npm run --workspace @kyberon/attesta build
  CHECKS_RAN+=("npm run --workspace @kyberon/attesta build")

  run_step "TypeScript tests" npm run --workspace @kyberon/attesta test
  CHECKS_RAN+=("npm run --workspace @kyberon/attesta test")

  run_step "Langflow package tests" env PYTHONPATH=python/src "${PYTHON_BIN}" -m pytest -q packages/langflow-attesta/tests
  CHECKS_RAN+=("PYTHONPATH=python/src ${PYTHON_BIN} -m pytest -q packages/langflow-attesta/tests")

  run_step "Dify package tests" env PYTHONPATH=python/src "${PYTHON_BIN}" -m pytest -q packages/dify-attesta/tests
  CHECKS_RAN+=("PYTHONPATH=python/src ${PYTHON_BIN} -m pytest -q packages/dify-attesta/tests")

  run_step "SBOM generation" ./scripts/generate_sbom.sh
  CHECKS_RAN+=("./scripts/generate_sbom.sh")

  run_step "Docs broken-links" bash -lc "cd docs && npx -y mintlify broken-links"
  CHECKS_RAN+=("cd docs && npx -y mintlify broken-links")
fi

mkdir -p "$(dirname "${REPORT_PATH}")"
{
  echo "# Pre-release Cut Report"
  echo
  echo "- Tag: \`${TAG}\`"
  echo "- UTC timestamp: \`${TIMESTAMP_UTC}\`"
  echo "- Commit: \`$(git rev-parse HEAD)\`"
  echo "- Branch: \`${CURRENT_BRANCH}\`"
  echo "- Python version source: \`${PYTHON_BIN}\`"
  echo "- Version parity: python=\`${PY_VERSION}\`, typescript=\`${TS_VERSION}\`"
  echo
  if [[ "${SKIP_CHECKS}" -eq 1 ]]; then
    echo "Preflight checks: **SKIPPED**"
  else
    echo "## Preflight checks executed"
    for cmd in "${CHECKS_RAN[@]}"; do
      echo "- \`${cmd}\`"
    done
  fi
} > "${REPORT_PATH}"

git tag -a "${TAG}" -m "Pre-release ${TAG}"

echo "[release] Created tag ${TAG}"
echo "[release] Wrote report ${REPORT_PATH}"

if [[ "${DO_PUSH}" -eq 1 ]]; then
  run_step "Push tag to origin" git push origin "${TAG}"
fi

echo "[release] Next steps:"
echo "[release] 1) Draft pre-release notes for ${TAG}"
echo "[release] 2) Verify workflow run for this tag"
echo "[release] 3) Validate install smoke tests for Python and npm"
