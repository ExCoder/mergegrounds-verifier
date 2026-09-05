# Threat model

Status: mandatory reading before deployment

## Security objective

A candidate revision is admitted only when every policy-required control has one
fresh, authentic, scope-complete result from an authorized independent producer for
the exact repository, candidate tree, protected base, canonical diff and policy.
Missing, malformed, ambiguous or unverifiable information produces denial.

This objective is admission integrity, not a proof that admitted code has no bugs.

## Assets

- protected branch and release eligibility;
- policy and subject materialization integrity;
- producer, waiver and decision signing identities;
- immutable evidence and decision history;
- availability of a fail-closed verification path;
- confidentiality of keys and any sensitive external reports referenced by digest.

## Trust boundaries

Trusted only after operator configuration:

- merge controller that derives the current subject from the source-control API;
- policy distribution system outside the candidate repository;
- isolated evidence producers and their post-collection signing paths;
- waiver authority separated from authors/producers;
- verifier runtime, dependency/image update path and decision key;
- required-check/ruleset configuration and the consumer verifying decisions;
- append-only evidence/decision store and trustworthy UTC time.

Untrusted:

- candidate source, branches, forks, PR text and repository workflows;
- AI-generated and human-generated code alike;
- candidate-produced reports, pass labels, signatures and claimed identities;
- mutable branch names, tags, action tags, package tags and dashboard state;
- public network requests and webhook bodies before authentication/replay checks.

## Attacker capabilities

Assume a contributor can fully control candidate files and processes; submit malformed
or huge JSON; reuse old evidence; replay another repository's evidence; reorder,
duplicate or conflict results; choose misleading Unicode/identities; trigger retries;
modify candidate workflows; exfiltrate any credential exposed to candidate execution;
and race a force-push/base update against check publication. Also assume one ordinary
scanner can miss a vulnerability. Do not assume contributors can read protected keys
or modify protected policy unless those boundaries were deployed incorrectly.

## Invariants and mitigations

| Threat | Required mitigation | Residual risk |
|---|---|---|
| evidence for another revision | exact subject and policy equality | trusted subject derivation can be wrong |
| stale/replayed pass | issuance, expiry, max age, base and diff binding | compromised time source/controller |
| self-approved candidate report | producer + key + isolation + toolchain-digest allowlists | producer boundary can itself be compromised |
| altered signed content | strict-subgroup Ed25519 over canonical closed-schema JSON | key theft or signing-service logic flaw |
| key alias crosses trust roles | globally unique public-key material in protected policy | separate keys can still share compromised custody |
| parser differential | duplicate rejection, finite numbers, strict schemas | cross-language canonicalization requires testing |
| skipped files represented as clean | exact required scope reconciliation | policy/producer may choose an insufficient scope |
| crash/timeout represented as pass | explicit `not_evaluated`; pass completeness rules | dishonest trusted producer |
| later pass hides fail | one result per control; duplicates/conflicts deny | controller must define new evaluation sets safely |
| forged exception | separate waiver identity, subject/scope/policy/TTL binding | authority misuse or key compromise |
| candidate satisfies required check | GitHub App identity restricted by ruleset | source-control configuration drift |
| force-push after decision | compare current head/base immediately before check | API/control-plane race or outage |
| dependency/image substitution | lock hashes, base digest, pinned CI actions | upstream compromise before review/update |
| denial-of-service by junk evidence | size/count caps; gateway rate/concurrency limits | fail-closed design intentionally permits denial |

## Non-goals

The verifier does not execute tools, isolate hostile code, prove human independence,
validate a finding's scientific truth, fetch references, build an SBOM, inspect GitHub
settings, protect secrets, provide transparency logging, revoke already-consumed
decisions, or stop an alternate unprotected merge/release path.

## Abuse cases that must remain denial

- unknown JSON members such as `allow_on_error`;
- a `pass` with findings or incomplete scope;
- empty findings for a claimed `fail`;
- `not_evaluated` labeled complete;
- a waiver issued by the evidence producer instead of the exception authority;
- duplicate evidence ID or two states for one control;
- signed evidence whose producer is allowed for a different control only;
- correct signature over a different repository/base/tree/policy;
- a decision that is unsigned, stale, or for a non-current PR head at the consumer.

The test suite contains executable negative cases for these classes.

## Compromise response

On producer/key/verifier compromise, remove the identity from protected policy,
stop admission, identify every decision referencing that identity, quarantine affected
revisions/artifacts, rotate keys, repair the boundary and rerun controls. This v1 core
does not automate fleet-wide revocation; the operator must maintain the searchable
append-only index needed for response.
