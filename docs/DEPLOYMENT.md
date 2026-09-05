# Deployment and operations

The included HTTP server is a narrow adapter, not a public SaaS perimeter. A real
deployment must complete every control below before treating a decision as merge
authority.

## Required topology

1. A protected controller reads repository/object identities from the hosting API,
   recomputes the canonical diff digest and creates the subject.
2. Independent producers fetch the exact immutable subject into ephemeral sandboxes,
   execute their control, validate structured output and sign only after hostile
   execution has ended or lost access to the signing service.
3. Producers append evidence to immutable storage through narrow authenticated APIs.
4. The verifier receives subject/policy/evidence from that protected plane, not from
   the candidate workspace, and signs its decision with a non-exportable identity.
5. A merge controller verifies the decision signature and current head/base, then
   updates the one required check identity authorized by a branch ruleset.

## Secrets and identities

- Prefer KMS/HSM or workload-identity signing over filesystem private keys.
- Give each producer and purpose different key material; never alias one public key
  under separate evidence, waiver or decision IDs.
- Do not expose producer or decision credentials to candidate processes, caches,
  artifacts, logs, PRs or fork workflows.
- Pin public keys in protected policy and pin the decision public key in the consumer.
- Define rotation overlap, revocation, audit and emergency stop procedures before use.
- Test that a revoked/unknown key deterministically denies.

`keygen` creates unencrypted PKCS#8 material for development. It is not a substitute
for production key custody.

## Policy and subject

- Store policy outside candidate repositories with two-person review and immutable
  version history.
- Use immutable repository database IDs rather than renameable display names where
  the source-control platform exposes them.
- Fetch commit/tree/base through an authenticated API and reject missing/shallow or
  replaced object identities.
- Define one canonical diff algorithm, including submodules/LFS/generated inputs, and
  conformance-test it across controller and producers.
- Use content-addressed scope manifests when `repository` is too coarse.
- Keep clock skew small and synchronize all trusted hosts.

## Network and HTTP edge

Run the service on a private network or loopback behind a gateway that provides mTLS
or workload identity, authorization, TLS, request replay protection, request and
concurrency limits, deadlines and controlled access logs. The default body cap is
4 MiB; reduce it for your evidence format. Never log raw evidence or referenced
reports if they may reveal source paths or security findings.

The stdlib server uses one thread per accepted connection. Production platforms must
bound concurrency at the proxy/runtime and set CPU/memory/process/network limits.

## Container

Build from a reviewed commit:

```bash
docker build --pull=false -t registry.example/mergegrounds-verifier:<git-sha> .
```

Run read-only with no shell need, dropped capabilities and read-only secret mounts:

```bash
docker run --rm --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --network=none \
  --mount type=bind,src=/protected/policy.json,dst=/run/policy.json,ro \
  mergegrounds-verifier:<git-sha> \
  policy-digest --policy /run/policy.json
```

The serving topology needs a narrowly scoped network path, so replace `--network=none`
with a policy-controlled internal network. Mount decision signing material only if
filesystem keys are accepted by your risk assessment.

## Evidence retention

Persist original bytes, canonical digest, receipt time, producer transport identity,
decision and decision signature in write-once or append-only storage. Index by subject,
policy, producer key and evidence digest for compromise response. Enforce retention
and access controls appropriate to finding metadata; references should be digests,
not bearer URLs.

## Release and updates

- Rebuild from pinned base/action/dependency identities only after review.
- Run unit/negative tests, schema checks, lint, container smoke and independent SAST.
- Verify the workflow-generated CycloneDX SBOM and GitHub/Sigstore provenance before
  promoting the exact workflow artifacts to an immutable release.
- Canary verifier updates against a corpus of historical admit/deny decisions.
- Treat schema/canonicalization/reason-code changes as compatibility-sensitive.
- Keep rollback images and previous public decision keys available for audit.

## Production readiness gate

Do not enable the required merge check until you have evidence for:

- independent security review and threat-model sign-off;
- producer sandbox escape/credential isolation tests;
- subject/diff conformance tests against real repositories;
- key rotation, revocation and disaster-recovery exercises;
- source-control ruleset audit showing no bypass/alternate check identity;
- load/DoS testing and observability without sensitive payload logging;
- verified release provenance, immutable release assets and deployment change control;
- incident runbook proving affected decisions can be found and quarantined.
