#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/benchmarks"

mkdir -p "${OUT_DIR}"

echo "Running Python benchmarks..."
python3 "${ROOT_DIR}/scripts/benchmark_python.py" \
  --output "${OUT_DIR}/python.json"

echo "Building TypeScript SDK..."
npm --prefix "${ROOT_DIR}" run --workspace @kyberon/attesta build >/dev/null

echo "Running TypeScript benchmarks..."
node "${ROOT_DIR}/scripts/benchmark_typescript.mjs" \
  --output "artifacts/benchmarks/typescript.json"

echo "Benchmark reports:"
echo "  - ${OUT_DIR}/python.json"
echo "  - ${OUT_DIR}/typescript.json"
