# Changelog

All notable changes will be documented here. The project follows Semantic Versioning
after 1.0; pre-1.0 minor versions may change schemas with explicit migration notes.

## 0.1.1 - 2026-09-05

- Require the release workflow to reject a tag whose target commit GitHub does not
  report as a valid verified signature.
- Require the release commit to carry the public `ExCoder` noreply author identity.
- Replace the ambiguous unsigned annotated-tag fallback with an explicit lightweight
  tag fallback whose lack of a separate tag-object signature is recorded in release
  notes.
- Mark v0.1.0 as superseded for promotion because its immutable release preserved an
  unsigned commit/tag without recording that exception in the release body. Its
  artifacts remain available for audit; v0.1.1 is the first promotion candidate.
- Keep the five v1 schemas byte-identical to v0.1.0.

## 0.1.0 - 2026-09-05

- Initial reference verifier core and CLI/HTTP adapter.
- Closed v1 subject, policy, evidence, waiver and decision schemas.
- Exact subject/policy/scope/producer/time/signature enforcement.
- Per-control tool, runner-image and workflow digest allowlists.
- Strict-subgroup Ed25519 verification and cross-role public-key reuse rejection.
- Fractional-time, parser-limit, output-error and startup signer fail-closed handling.
- Deterministic signed decisions and extensive negative tests.
- Threat model, deployment guide and GitHub App integration blueprint.
- Hash-locked runtime/build environments, built-wheel smoke tests, CycloneDX SBOM and
  GitHub/Sigstore release provenance workflow.
