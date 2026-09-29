# Security Policy

Refract is a financial protocol that custodies user funds. We take security
seriously and appreciate responsible disclosure.

## Status

🔍 **Audit Readiness & Scoping Phase.** Refract is actively preparing for an independent third-party security audit prior to mainnet launch. All pre-audit hardening findings, scope boundaries, and the live remediation board are tracked in [AUDIT_TRACKING.md](AUDIT_TRACKING.md).

Do not deploy to mainnet or custody production value until the external audit engagement has concluded and all critical findings are formally signed off.

## Security Artifacts & Runbooks

- **Audit Scoping & Remediation Tracker**: [AUDIT_TRACKING.md](AUDIT_TRACKING.md)
- **Griefing-Cost Analysis**: [GRIEFING_ANALYSIS.md](GRIEFING_ANALYSIS.md)
- **Incident Response & Recovery Runbook**: [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, email **security@refract.example** with:

- A description of the issue and its impact
- Steps to reproduce (proof-of-concept where possible)
- Affected contract/service and version/commit

We aim to acknowledge reports within **72 hours** and to provide a remediation
timeline after triage. We will credit reporters who wish to be named once a fix
ships.

## Scope

In scope: the smart contracts, the backend services, and the web app in the
Refract repositories. Out of scope: third-party dependencies (report upstream),
testnet-only configuration, and theoretical issues without a practical impact.

## Known limitations (by design, pre-audit)

- The oracle is **permissioned** (admin/relayer submitted). Decentralizing it is
  on the roadmap.
- Trigger thresholds are set at deployment and changed only via admin.
- Mainnet deployment is strictly gated until an external audit completes and sign-offs are logged in [AUDIT_TRACKING.md](AUDIT_TRACKING.md).
