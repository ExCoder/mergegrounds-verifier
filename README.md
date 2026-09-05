# MergeGrounds Verifier

**Independent, fail-closed admission decisions for exact-revision evidence.**

MergeGrounds Verifier is a reference decision core and a small HTTP/CLI adapter.
It accepts evidence created by separately operated producers, validates the exact
repository/commit/tree/base/diff/policy binding, verifies Ed25519 signatures and
emits deterministic `admit` or `deny` JSON.

Project: [MergeGrounds](https://github.com/ExCoder/mergegrounds) ·
[website](https://mergegrounds.chawax.chatgpt.site)

> This repository is not a sandboxed multi-stack test executor. It does not run
> candidate code, prove that a scanner is correct, configure GitHub rulesets, or
> make code “safe.” It is not production-ready until an operator supplies protected
> identities, isolated evidence producers, policy, storage, networking and merge
> enforcement described in [Deployment](docs/DEPLOYMENT.md).

## What the verifier enforces

- Draft 2020-12 JSON Schemas with closed fields at every security-sensitive object;
- duplicate JSON-member rejection before schema validation;
- exact repository, commit, tree, base commit and canonical-diff binding;
- exact policy ID, version and canonical SHA-256 digest binding;
- per-control producer, producer-key, isolation-class, tool, runner-image and
  workflow-digest allowlists;
- Ed25519 signatures over a documented canonical JSON representation;
- strict invocation ordering, expiry, freshness, maximum TTL and clock skew;
- exact required scope with evaluated/omitted reconciliation;
- explicit `pass`, `fail`, `not_evaluated`, and signed/scoped `waived` semantics;
- exactly one evidence document per required control;
- denial on missing, malformed, stale, conflicting, duplicate or unexpected evidence;
- stable reason codes, ordered control summaries and content digests;
- optional policy-bound Ed25519 signing of the final decision.

The active policy and subject are trusted inputs. They must be supplied by a
control plane that the candidate repository cannot modify.

## Architecture

```text
untrusted candidate source
        │ exact immutable subject
        ▼
isolated producers A/B/... ── signed evidence ──► append-only store
                                                    │
protected subject + policy ─────────────────────────┤
                                                    ▼
                                      MergeGrounds Verifier
                                                    │
                                      signed admit / deny JSON
                                                    ▼
                                 protected GitHub required check
```

Signing a candidate-produced claim does not make it trusted. A producer is trusted
only when its workflow, credentials and signing boundary are outside candidate
control and the policy explicitly authorizes its identity for that control.

## Install for development

This checkout pins Python 3.11.16 and
[uv 0.12.10](https://github.com/astral-sh/uv/releases/tag/0.12.10); install that uv
release before running project commands. CI and the container use the same Python
security patch. The runtime and build locks contain exact versions and artifact
hashes.

```bash
uv --version  # must report 0.12.10
uv python install
uv sync --frozen --group build
uv run mergegrounds-verifier --help
uv run coverage run -m unittest discover -s tests -v
uv run coverage report --fail-under=90
uv run ruff check src tests
```

Runtime-only environments can use `pip --require-hashes -r requirements.lock`.

## Reproducible source-checkout walkthrough

The following runs only from a full Git source checkout because test fixtures are
deliberately excluded from wheels and source distributions. It uses compromised keys
under `tests/fixtures`; never use them for a real repository.

```bash
uv run mergegrounds-verifier sign \
  --kind evidence \
  --input examples/evidence.unsigned.example.json \
  --private-key tests/fixtures/producer-private.pem \
  --key-id example-producer-2026-09 \
  --output /tmp/mergegrounds-example-evidence.json

uv run mergegrounds-verifier verify \
  --policy examples/policy.example.json \
  --subject examples/subject.example.json \
  --evidence /tmp/mergegrounds-example-evidence.json \
  --now 2026-09-05T12:00:00Z
```

The second command exits `0` and prints an unsigned demonstration decision with
`"decision": "admit"`. Production callers must configure a protected decision
signing key and verify that signature before setting a required check.

## CLI

```text
verify          Validate all evidence and emit a decision (0 admit, 1 deny, 2 bad invocation)
policy-digest   Validate a policy and print its canonical SHA-256 digest
sign            Sign an unsigned evidence or waiver object; never overwrites a signature
keygen          Generate an Ed25519 PKCS#8 private key (0600) and raw public key
canonicalize    Render the exact bytes covered by document signatures
serve           Expose GET /healthz and POST /v1/verify, bound to loopback by default
```

For a replayable decision, pass an explicit UTC `--now`. Freshness makes a decision
time-dependent by design; identical inputs and evaluation time produce identical
JSON and signatures.

## HTTP adapter

```bash
uv run mergegrounds-verifier serve \
  --policy /run/secrets/policy.json \
  --decision-signing-key /run/secrets/decision-key.pem \
  --decision-key-id operator-decision-2026-09
```

`POST /v1/verify` accepts exactly:

```json
{"subject": {"...": "trusted subject v1"}, "evidence": [{"...": "evidence v1"}]}
```

The adapter intentionally has no public-edge authentication, TLS, webhook parser,
rate limiter or durable store. Put it behind an authenticated internal gateway; do
not expose it directly to the internet. Denials return HTTP 422, invalid requests
return 4xx, and responses use `Cache-Control: no-store`.

## Schemas and semantics

Normative schemas ship inside `src/mergegrounds_verifier/schemas/` and are included
in the wheel. Their canonical HTTPS copies live under the
[site schema directory](https://mergegrounds.chawax.chatgpt.site/schemas/). See
[Format specification](docs/FORMAT_SPEC.md) for canonicalization, signature boundaries,
state semantics and reason-code behavior.

| Input | Authority | Important binding |
|---|---|---|
| subject | merge controller | repository, candidate, tree, base, diff |
| policy | protected operator config | controls, producers, keys, scope, freshness |
| evidence | isolated producer | subject + active policy + execution + result |
| waiver | separate exception authority | exact subject + policy + control + scope + TTL |
| decision | verifier | all consumed evidence digests and normalized controls |

## Container

The image uses a digest-pinned Python base, installs only hash-locked runtime
dependencies, runs as UID/GID 65532 and defaults to the CLI help. Mount policy and
keys read-only; never bake operator secrets into an image.

```bash
docker build -t mergegrounds-verifier:local .
docker run --rm mergegrounds-verifier:local --help
```

## Before production

Read these in order:

1. [Threat model](docs/THREAT_MODEL.md)
2. [Deployment and operations](docs/DEPLOYMENT.md)
3. [GitHub App integration](docs/GITHUB_APP_INTEGRATION.md)
4. [Known limitations](docs/LIMITATIONS.md)
5. [Security policy](SECURITY.md)

Replace every example identity/key, create real CODEOWNERS teams, run independent
security review and conformance tests, and enforce the signed decision through a
GitHub ruleset that candidate workflows cannot satisfy.

## License

Apache-2.0. See [LICENSE](LICENSE).
