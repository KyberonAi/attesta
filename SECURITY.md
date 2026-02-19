# Security Policy

## Supported Versions

Security fixes are applied to:

- the latest `main` branch
- the latest published `0.1.x` release line

Older versions are not guaranteed to receive security patches.

## Reporting A Vulnerability

Do not open public issues for suspected vulnerabilities.

Report privately with:

- affected component and version
- reproduction steps or proof-of-concept
- impact assessment
- suggested mitigation (if available)

Channels:

- GitHub Security Advisory in this repository (preferred)
- private email to maintainers listed in `CODEOWNERS`

## Response Targets

- acknowledgment: within 3 business days
- initial triage/severity: within 7 business days
- remediation plan for confirmed high/critical findings: within 14 calendar days

If timelines slip, maintainers should post a status update in the security advisory thread.

## Disclosure Process

1. Maintainers validate and classify severity (CVSS + exploitability context).
2. A fix is prepared and tested privately when possible.
3. Patched versions are released with remediation notes.
4. Public disclosure follows after patches are available.

## Security Controls In CI

The repository enforces these controls via GitHub Actions:

- CodeQL (`.github/workflows/security.yaml`)
- Semgrep SAST (`.github/workflows/security.yaml`)
- Gitleaks secrets scanning (`.github/workflows/security.yaml`)
- dependency audits (`pip-audit` and `npm audit --workspace @kyberon/attesta --audit-level=high`)
- SBOM generation (CycloneDX for Python + TypeScript)
- artifact provenance attestations for release outputs and SBOM artifacts

## Dependency Risk Policy

- high/critical findings in direct dependencies for releasable artifacts must be fixed before release.
- exceptions must be recorded in `security/dependency-exceptions.md` with owner, rationale, and expiry date.
- exceptions are temporary and must be reviewed at least once per release cycle.
