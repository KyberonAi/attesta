#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/sbom"
PYTHON_BIN=""

for candidate in python3.12 python3.11 python3; do
  if ! command -v "${candidate}" >/dev/null 2>&1; then
    continue
  fi
  if "${candidate}" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
  then
    PYTHON_BIN="${candidate}"
    break
  fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "Python 3.11+ is required to generate SBOMs." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "Generating Python SBOM..."
"${PYTHON_BIN}" -m pip install --upgrade pip >/dev/null
"${PYTHON_BIN}" -m pip install cyclonedx-bom >/dev/null
"${PYTHON_BIN}" -m pip install -e "${ROOT_DIR}/python[yaml]" >/dev/null
"${PYTHON_BIN}" -m cyclonedx_py environment \
  --of JSON \
  --output-file "${OUT_DIR}/python.cdx.json" \
  "$(command -v "${PYTHON_BIN}")"

echo "Generating TypeScript SBOM..."
(
  cd "${ROOT_DIR}"
  npm ci >/dev/null
  npx -y @cyclonedx/cyclonedx-npm \
    --output-format JSON \
    --output-file "${OUT_DIR}/typescript.cdx.json" \
    --workspace @kyberon/attesta >/dev/null
)

echo "SBOM artifacts written to ${OUT_DIR}"
