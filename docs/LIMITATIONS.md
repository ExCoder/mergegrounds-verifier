# Known limitations

Version 0.1.1 is a reference implementation, not a production certification.

- It verifies decisions but does not execute linters, tests, mutation testing,
  scanners, fuzzers or builds in sandboxes.
- Operator policy and trusted subject arrive out of band and are not themselves
  fetched or attested by this process.
- The built-in HTTP adapter lacks TLS, authentication, authorization, persistent
  storage, queueing, rate limiting and bounded worker pools.
- Ed25519 filesystem keys are supported for portability; production should prefer a
  KMS/HSM/workload signing service and non-exportable keys.
- References are content digests only. This version does not fetch or traverse a full
  evidence graph, prove append-only inclusion, or query a transparency log.
- `scope` tokens are operator-defined. The verifier reconciles them exactly but does
  not discover whether the protected scope manifest itself covers every relevant file.
- Canonical JSON is the documented project profile, not RFC 8785. Cross-language
  producers need conformance vectors.
- There is no online key revocation or historical decision quarantine mechanism.
  Policy rotation stops future admission; fleet-wide response belongs to the control plane.
- Multiple documents for one control always deny. The controller must construct a new
  evaluation set for an explained retry instead of asking this core to pick a winner.
- The service clock is trusted and freshness makes decisions time-dependent.
- The release workflow emits GitHub/Sigstore provenance and a dependency SBOM, but
  v0.1.1 does not claim byte-for-byte reproducible setuptools source archives, SLSA
  Build Level 3, or end-to-end deployment provenance.
- Repository and canonical-diff identity correctness is only as strong as the
  protected controller that supplies them.
- A valid `pass` proves that an authorized producer signed a schema-complete result;
  it does not prove the underlying tool or test oracle is sound.

These limits are intentional where silently pretending would create false assurance.
