# Contributing

Thank you for helping make fail-closed admission easier to audit.

## Development

The source checkout requires the exact toolchain declared in `.python-version` and
`pyproject.toml`: Python 3.11.16 and uv 0.12.10.

```bash
uv --version  # must report 0.12.10
uv python install
uv sync --frozen --group build
make check
```

Never add real keys, repository evidence, customer paths, private findings or tokens.
Private-key material is prohibited outside `tests/fixtures/`, whose keys are public
and intentionally compromised.

## Change expectations

- Start with a threat/behavior statement and an adversarial test.
- Preserve closed schemas and deterministic output.
- Treat parsing/verification uncertainty as denial.
- Document compatibility changes to schemas, canonical bytes or reason codes.
- Add a negative test for every security bug before fixing it.
- Keep runtime dependencies minimal, exactly pinned and hash-locked.
- Pin GitHub actions and base images by immutable digest.
- Update threat model/limitations when a control moves between implemented and external.

Run:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run coverage run -m unittest discover -s tests -v
uv run coverage report --fail-under=90
uv run pip-audit --requirement requirements.lock --disable-pip
uv run pip-audit --requirement build-requirements.lock --disable-pip
docker build -t mergegrounds-verifier:test .
docker run --rm mergegrounds-verifier:test --version
```

## Pull requests

Explain the trust boundary affected, failure mode, evidence proving the change, and
rollback/compatibility impact. Small reviewable changes are preferred. Security-
sensitive changes require an independent maintainer and security owner after the real
CODEOWNERS teams and branch rules are configured.

By contributing, you agree that your contribution is licensed under Apache-2.0 and
that you have the right to submit it.
