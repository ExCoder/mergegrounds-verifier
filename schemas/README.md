# Packaged schemas

The normative, installable Draft 2020-12 schemas live in
`src/mergegrounds_verifier/schemas/` so wheels and containers cannot omit them.
This directory is a discovery pointer rather than a second, drift-prone copy.

Canonical browser-resolvable copies are published at
`https://mergegrounds.chawax.chatgpt.site/schemas/<name>.schema.json`. Their bytes
must match the corresponding packaged v1 schema before a site release is promoted.
