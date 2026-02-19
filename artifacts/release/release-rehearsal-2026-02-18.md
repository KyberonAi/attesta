# Release Rehearsal Report

Date: 2026-02-18  
Scope: OSS launch readiness rehearsal

## Executed Checks

- `PYTHONPATH=python/src pytest -q python/tests/test_gate.py python/tests/test_security.py::TestApprovalTimeout python/tests/test_events.py python/tests/test_new_features.py::TestAttestaFromConfig python/tests/test_config.py`  
  Result: pass (`112 passed`)

- `PYTHONPATH=python/src pytest -q python/tests`  
  Result: pass (`516 passed`)

- `PYTHONPATH=python/src pytest -q packages/langflow-attesta/tests`  
  Result: pass (`5 passed`)

- `PYTHONPATH=python/src pytest -q packages/dify-attesta/tests`  
  Result: pass (`5 passed`)

- `./scripts/check_release_boundary.sh`  
  Result: pass

- `npm run --workspace @kyberon/attesta typecheck`  
  Result: pass

- `npm run --workspace @kyberon/attesta build`  
  Result: pass

- `npm run --workspace @kyberon/attesta test`  
  Result: pass (`4 tests`)

- `npm --workspace @kyberon/attesta pack --dry-run`  
  Result: pass

- `npm audit --workspace @kyberon/attesta --audit-level=high`  
  Result: pass (`found 0 vulnerabilities`)

- `cd python && python3.11 -m pip_audit`  
  Result: pass (`No known vulnerabilities found`)

- `cd python && python3.11 -m build`  
  Result: pass (sdist and wheel built)

- `./scripts/run_benchmarks.sh`  
  Result: pass (reports written to `artifacts/benchmarks/python.json` and `artifacts/benchmarks/typescript.json`)

- `cd docs && npx -y mintlify broken-links`  
  Result: pass (`no broken links found`)

## Notes

- `pip_audit` cannot audit the local package name `attesta (0.1.0)` because it is
  not resolved from PyPI in this local workspace context.
- Final human sign-off should be recorded in `/Users/rsamal/project/research/attesta/RELEASE_CHECKLIST.md`.

Signed: `Codex automation run`
