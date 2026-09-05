# GitHub App integration guide

This repository supplies the decision core, not a complete GitHub App. The App is a
separate protected service because code in a pull request must not control the judge
that decides whether that pull request may merge.

## Minimal App permissions

Start from no permissions and grant only what the implementation uses:

- metadata: read (implicit);
- contents: read, to resolve immutable commits/trees and protected base;
- pull requests: read, to observe head/base and synchronize events;
- checks: write, to create/update the dedicated MergeGrounds check run.

Avoid administration/content-write permissions. Subscribe narrowly to pull request
and installation/repository events. Validate the webhook HMAC over raw bytes, reject
old/replayed delivery IDs, verify installation/repository IDs, and perform work from
the API's current state rather than trusting webhook fields alone.

## Canonical GitHub subject

Use an immutable identity such as `github://repository/<repository_database_id>` as
`repository`. Resolve candidate and base full OIDs through the installation token.
Resolve the candidate Git tree OID independently. Compute the canonical diff digest
in the controller with a documented algorithm; do not trust a digest from the PR.

Before publishing a success conclusion, re-fetch:

- repository database ID;
- PR current head OID;
- protected base OID/current ruleset assumptions;
- candidate tree OID;
- active protected policy digest.

Any change invalidates the decision and restarts evaluation.

## Safe event flow

```text
signed webhook
  → authenticate delivery + load current PR
  → derive immutable subject
  → request independent producers
  → collect append-only signed evidence
  → POST subject/evidence to protected verifier
  → verify signed decision in controller
  → re-read head/base/policy
  → checks.create/update for exact head SHA
```

Use a stable external correlation ID, but do not treat PR number/run ID as subject
identity. Make event handling idempotent. Record GitHub delivery/check IDs beside the
decision digest.

## Workflow boundary

Candidate GitHub Actions may request evaluation or upload untrusted diagnostic
artifacts, but they cannot possess producer keys, write the protected evidence store,
select policy/scope, or set the required check. Do not use `pull_request_target` to
check out and execute candidate code with base-repository credentials. If GitHub-hosted
runners execute controls, isolate signing behind an authenticated collector that
derives subject/identity server-side and receives only validated results after the
candidate process is gone.

## Ruleset

Create a GitHub ruleset requiring the exact App-owned check name and, where supported,
the expected App/source identity. Require pull requests, current-branch checks, review,
conversation resolution and signed/linear history as appropriate. Restrict bypass to
an audited break-glass role and alert on use. Prevent candidate workflows or ordinary
tokens from creating a same-named satisfying check.

The App should map only a verified, signed `admit` for the current subject to GitHub
`success`. Map every `deny`, parse/transport error, verifier outage, unsigned decision,
head/base race and unknown state to failure or leave the check incomplete according
to a documented fail-closed timeout. Never map `not_evaluated` to neutral success.

## GitHub's role and residual risk

GitHub check state is mutable presentation. Retain the signed decision and consumed
evidence independently. Audit rulesets and App installation permissions continuously.
A compromised App/controller or bypass-capable administrator remains in the trusted
computing base; this verifier cannot repair an alternate path around the required check.
