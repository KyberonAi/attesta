## Summary

Describe what changed and why.

## Change Type

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation only
- [ ] Refactor
- [ ] Security hardening
- [ ] Build/CI

## Validation

- [ ] `PYTHONPATH=python/src pytest -q python/tests`
- [ ] `npm run --workspace @kyberon/attesta typecheck`
- [ ] `npm run --workspace @kyberon/attesta build`
- [ ] `npm run --workspace @kyberon/attesta test`
- [ ] `./scripts/check_release_boundary.sh`

List any commands you skipped and why.

## Compatibility

- [ ] No breaking API changes
- [ ] Breaking changes are documented in `docs/guides/migration.mdx`

## Security Checklist

- [ ] No new secrets or credentials committed
- [ ] New dependencies were reviewed for license and vulnerability posture
- [ ] Security implications are documented (if applicable)

## Docs

- [ ] Public behavior changes are reflected in docs
- [ ] README/docs links were checked
