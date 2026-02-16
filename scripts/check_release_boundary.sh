#!/usr/bin/env bash
set -euo pipefail

fail=0

echo "[boundary] Checking tracked file boundary..."

if git ls-files | rg -q '^\.rollback_backup_'; then
  echo "[boundary] ERROR: rollback backup files are tracked:"
  git ls-files | rg '^\.rollback_backup_'
  fail=1
fi

if git ls-files | rg -q '^\.venv/'; then
  echo "[boundary] ERROR: virtualenv files are tracked:"
  git ls-files | rg '^\.venv/'
  fail=1
fi

if git ls-files | rg -q '(^|/)attesta-proprietary(/|$)'; then
  echo "[boundary] ERROR: proprietary workspace paths are tracked in OSS repo:"
  git ls-files | rg '(^|/)attesta-proprietary(/|$)'
  fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
  echo "[boundary] FAILED"
  exit 1
fi

echo "[boundary] OK"
