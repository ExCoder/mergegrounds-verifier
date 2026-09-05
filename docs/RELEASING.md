# Release procedure

Releases are maintainer-controlled promotions of artifacts built from a protected
tag by GitHub Actions. Never publish workstation-built files or mix artifacts from
different runs.

## Preconditions

- `main` is protected, green and contains the intended release commit.
- `pyproject.toml`, `src/mergegrounds_verifier/__init__.py`, `CHANGELOG.md` and the
  intended `v<version>` tag agree.
- Runtime and build locks were explicitly reviewed and both audits pass.
- GitHub release immutability and Private Vulnerability Reporting are enabled.
- The release commit is reviewed and has a verified signature. Use a signed annotated
  tag when a maintainer signing identity is configured; otherwise record that the tag
  itself is unsigned and rely on its immutable-release lock plus workflow provenance.

An explicit local cleanliness check, when preparing metadata, is:

```bash
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

A bare `git status --porcelain` is not a gate: it exits zero even when it prints dirty
paths. No local artifact is promoted by this procedure.

## Build the candidate from the tag

For `0.1.0`, create `v0.1.0` at the exact protected-main commit and push only the tag.
The `release-assets` workflow then independently:

1. checks that the tag, project version and source version match;
2. proves the tagged commit is contained in `origin/main` and the checkout is clean;
3. installs hash-locked runtime, development and build dependencies;
4. runs lint, the complete test/coverage suite and both dependency audits;
5. builds without an untracked isolated build environment;
6. rejects private-key material and missing packaged schemas;
7. installs and exercises the exact built wheel in a fresh environment;
8. emits a CycloneDX dependency SBOM and flat `SHA256SUMS` file;
9. creates GitHub/Sigstore provenance plus an SBOM attestation; and
10. uploads one reviewable candidate bundle for seven days.

The workflow deliberately cannot create or modify a GitHub Release: its token has no
`contents: write`. Promotion remains a separate, auditable maintainer action.

## Verify and promote one workflow bundle

Download the artifact from the single successful run for the tag into a fresh
directory. Do not download into the source checkout.

```bash
release_dir="$(mktemp -d)"
run_id="$(gh run list --workflow release-assets.yml --branch v0.1.0 \
  --status success --json databaseId --jq '.[0].databaseId')"
gh run download "$run_id" --name mergegrounds-verifier-v0.1.0 --dir "$release_dir"
(cd "$release_dir/dist" && sha256sum -c ../SHA256SUMS)
release_sha="$(gh api repos/ExCoder/mergegrounds-verifier/commits/v0.1.0 --jq .sha)"
for artifact in "$release_dir"/dist/*; do
  gh attestation verify "$artifact" \
    --repo ExCoder/mergegrounds-verifier \
    --signer-workflow ExCoder/mergegrounds-verifier/.github/workflows/release-assets.yml \
    --source-ref refs/tags/v0.1.0 \
    --source-digest "$release_sha"
done
```

Review the SBOM and workflow run, install the wheel again if desired, and then create
the immutable release from those exact files:

```bash
gh release create v0.1.0 "$release_dir"/dist/* "$release_dir/SHA256SUMS" \
  --verify-tag \
  --title "MergeGrounds Verifier v0.1.0" \
  --notes-file CHANGELOG.md
```

After GitHub reports the release immutable, verify every downloaded distribution and
SBOM against the flat checksum manifest and its provenance attestation once more.
Record the release URL, tag commit, workflow run, checksums and verification result in
the launch evidence ledger.

`SOURCE_DATE_EPOCH` stabilizes the wheel in the current toolchain, but v0.1.0 does not
claim a byte-for-byte reproducible setuptools source archive or SLSA Build Level 3.
The source-checkout walkthrough depends on deliberately compromised test fixtures;
those fixtures are correctly absent from wheels and source distributions.
