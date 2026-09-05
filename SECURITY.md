# Security policy

## Supported versions

This repository is a pre-1.0 reference implementation. Security fixes are applied
only to the latest release and `main`. No release is production-certified.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting in the
[canonical repository](https://github.com/ExCoder/mergegrounds-verifier/security/advisories/new).
Do not open a public issue, attach production evidence, disclose private repository
content, or send private keys. Include the affected commit/version, attack preconditions,
minimal redacted reproduction, impact, and suggested mitigation if known.

The maintainers aim to acknowledge a complete report within three business days and
provide a triage update within seven. These are response targets, not a guarantee.
Coordinated disclosure timing will be agreed with the reporter based on exploitability
and deployment impact.

Private Vulnerability Reporting must remain enabled in repository settings. If it is
unavailable, stop publishing security contact claims until a private replacement exists.

## Security-sensitive changes

Changes to canonicalization, schemas, state semantics, policy validation, signature
handling, freshness, scope, reason codes, decision output, dependencies, container,
CI, CODEOWNERS, or deployment guidance require security-owner review and negative
tests. A passing happy path is not sufficient.

## Scope clarification

Reports that show admission after malformed, stale, conflicting, wrongly bound or
untrusted evidence are security issues. Missing scanner/executor functionality is a
documented non-goal of this repository; sandbox/executor vulnerabilities belong to
the corresponding producer project.
