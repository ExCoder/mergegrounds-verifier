# Test-only keys

These deterministic repository fixtures are public and compromised by definition.
The narrowly scoped `.github/secret_scanning.yml` exclusion prevents them from
creating false-positive push-protection alerts. Do not broaden that exclusion.
They exist only to exercise signature verification. Never use them outside tests or
examples, and never copy them into an operator deployment.
