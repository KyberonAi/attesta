# Attesta Release Checklist

Date: `YYYY-MM-DD`  
Release Version: `vX.Y.Z`

## 1. Product Behavior

- [ ] Python timeout policy matrix verified (`deny`, `allow`, `escalate`)
- [ ] TypeScript timeout policy matrix verified (`deny`, `allow`, `escalate`)
- [ ] `ESCALATED` verdict path validated in SDKs and wrappers
- [ ] Docs match implemented runtime behavior

## 2. Quality Gates

- [ ] `./scripts/check_release_boundary.sh`
- [ ] `PYTHONPATH=python/src pytest -q python/tests`
- [ ] `npm run --workspace @kyberon/attesta typecheck`
- [ ] `npm run --workspace @kyberon/attesta build`
- [ ] `npm run --workspace @kyberon/attesta test`
- [ ] `PYTHONPATH=python/src pytest -q packages/langflow-attesta/tests`
- [ ] `PYTHONPATH=python/src pytest -q packages/dify-attesta/tests`

## 3. Security

- [ ] `pip-audit` completed with no unresolved high-severity direct dependencies
- [ ] `npm audit --workspace @kyberon/attesta --audit-level=high` passes
- [ ] `./scripts/generate_sbom.sh` executed and artifacts reviewed
- [ ] Release provenance attestations generated for Python/npm artifacts
- [ ] `security/dependency-exceptions.md` reviewed and expirations updated
- [ ] `SECURITY.md` reviewed for current reporting process

## 4. Performance Evidence

- [ ] `./scripts/run_benchmarks.sh` executed
- [ ] Benchmark artifacts stored under `artifacts/benchmarks/`
- [ ] Published latency claims cite measured p50/p95 values

## 5. OSS Launch Readiness

- [ ] `README.md` links and badges resolve
- [ ] `OSS_SCOPE.md` reflects current OSS/proprietary boundary
- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS` present
- [ ] Release notes include migration notes for `fail_mode` semantics

## Sign-off

Maintainer Name: `________________`  
Signature/Initials: `________________`  
Approved At (UTC): `________________`
