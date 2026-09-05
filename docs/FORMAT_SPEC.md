# Format and decision specification

Status: reference implementation contract for v1

## Strict JSON

Input is UTF-8 JSON. Duplicate object member names, `NaN`, `Infinity`, oversized
documents and unknown schema fields are errors. Security-sensitive schemas set
`additionalProperties: false` recursively. Arrays that model sets reject duplicates.
Policy fields declared as integers must use an integral JSON representation such as
`64`, not a mathematically integral float such as `64.0` or `64e0`.

The signing representation is UTF-8 JSON with object keys sorted lexicographically,
no insignificant whitespace, unescaped Unicode and finite JSON numbers only. The
top-level `signature` member is removed before encoding. This profile is implemented
by `canonical.canonical_bytes`; it is intentionally not claimed to be RFC 8785.
Producers in another language must pass cross-language conformance vectors before
their identity is allowlisted.

SHA-256 content identifiers are lowercase `sha256:<64 hex>` over that same encoding.
Ed25519 public keys and signatures are unpadded canonical base64url.
Trusted public keys must be canonical points in the prime-order subgroup. The policy
also rejects reuse of the same public-key material under another key ID, owner or
purpose; the signature envelope's key ID selects policy, but is not itself signed.

## Trusted subject

The merge controller supplies the subject independently from evidence:

- canonical immutable repository identity;
- candidate commit object ID;
- candidate tree object ID;
- protected base commit object ID;
- canonical diff SHA-256 digest.

Every evidence document must reproduce all five values exactly. Branch names, PR
numbers and URLs are descriptive metadata elsewhere; they do not replace an object
identity. Git SHA-1 and SHA-256 object IDs are accepted to support both object formats.

## Policy binding

The policy digest is `sha256_digest(the complete policy JSON)`. Evidence and waivers
bind policy ID, version and digest. A policy edit invalidates old evidence even when
the human-readable version was accidentally left unchanged.

For each required control, policy defines exactly:

- allowed producer identities;
- allowed producer isolation classes;
- allowed tool, runner-image and workflow digests;
- maximum evidence age/TTL;
- exact required scope tokens;
- whether a separate waiver authority may authorize a non-pass state.

Producer identities and waiver-authority identities are disjoint; assigning the same
identity to both roles makes the policy invalid even when the keys differ.

Policy is not signed inside this implementation because its source is an operator
trust input. Store and mount it from a protected configuration system; never read it
from the candidate checkout.

## Result states

- `pass`: result and scope are complete and findings are empty.
- `fail`: a complete determination contains at least one structured finding. It
  denies admission even if evaluation stopped after a decisive failure.
- `not_evaluated`: no complete determination exists. It never satisfies a control.
- `waived`: a complete evidence envelope contains a separately signed, unexpired
  exception for this exact subject, policy, control and required scope. The policy
  must mark the control waivable. Its underlying state is `fail` or `not_evaluated`.

Only `pass` and a fully valid `waived` state satisfy a required control. A waiver
does not mutate the underlying result or erase its finding.

## Scope

`expected` must equal the policy's `required_scope`. `evaluated` and the `item`
values from `omitted` must be disjoint and reconcile exactly to `expected`.
`scope.complete` is true if and only if every expected item was evaluated and no
item was omitted. A passing result requires complete scope.

Scope tokens are opaque canonical identifiers chosen by the protected policy
materializer, such as `repository`, `component:payments`, or content-addressed file
manifest IDs. The verifier does not discover files; that is a trusted producer job.

## Cardinality and conflicts

Admission requires exactly one evidence document for every required control.
Repeated evidence IDs, repeated identical documents, and distinct documents for the
same control deny admission. Retries therefore cannot silently erase earlier fails;
the controller must create a new evaluation set after a justified subject/policy/tool
transition and retain the old set for audit.

Unexpected controls also deny. This makes a producer/policy disagreement visible
instead of silently discarding evidence.

## Time

All timestamps are explicit RFC 3339 UTC strings ending in `Z`. Invocation must obey
`started_at <= finished_at <= issued_at < expires_at`. The verifier rejects evidence
issued beyond the configured future skew, evidence expiring at or before evaluation time,
evidence older than control `max_age_seconds`, or a self-declared TTL longer than the
same maximum. Waivers receive equivalent checks.
Fractional seconds are preserved through comparison and decision output; no expiry
or future-skew check rounds the evaluation time down.

## Decisions

Controls, evidence digests, reason codes and issues are sorted. `decision_digest`
hashes the decision object before the digest/signature members exist. When configured,
the final document (including its digest) is signed with the policy-bound decision
key. The consumer must require `signed: true`, pin the expected public key/purpose,
verify the signature, verify the current subject again, and enforce only `admit`.

Unsigned decisions exist for local diagnostics and are not merge authority.
