# `cycles-correspondence-vectors.json` provenance

Vendored byte for byte from the TypeScript SDK. Nothing in this repository
generates or edits it. A change to its bytes is a change to what both
implementations are asserted to do, and it belongs upstream, in the repository
named below, not here.

| field | value |
|---|---|
| source repository | `agent-passport-system/agent-passport-system` (TypeScript SDK) |
| source path | `tests/v2/payment-rails/cycles-correspondence-vectors/vectors.json` |
| generator | `tests/v2/payment-rails/cycles-correspondence-vectors/generate.ts` in that repository |
| source commit | `ababe0ffc8a1383ccc00691fde6289bc1bd2e70a` (`ababe0f`, "Merge #237: test(cycles): language-neutral correspondence vectors") |
| rule in force since | `agent-passport-system` 8.0.0 |
| SHA-256 of the file as vendored | `38b732b990dd11d0f016a94fa2d865f685c34005e72b70ea35d5140534b2aa31` |

`tests/cross_impl/test_cycles_correspondence_vectors.py` asserts that SHA-256
against the file on disk, so the vendored copy cannot drift from the bytes this
port was checked against without a test saying so.

To re-fetch the exact bytes:

```
git -C <agent-passport-system> show ababe0f:tests/v2/payment-rails/cycles-correspondence-vectors/vectors.json
```

## Renamed on vendoring

`vectors.json` upstream, `cycles-correspondence-vectors.json` here, matching the
`<name>-vectors.json` shape the other vendored vector files in this directory
use.

## What it covers

The receipt to envelope correspondence rule for Cycles permit and release
receipts, 13 cases: two positive controls, nine correspondence failures, the
rule that the hash check runs before correspondence, and the rule that denials
get no correspondence check. The unaltered envelopes were signed by the Cycles
server. Cases that alter an envelope re-sign it with a published, test-only key
derived from a fixed seed in `generate.ts`. The receipt issuer key is derived the
same way, so the signatures are reproducible, and the Python test re-signs every
receipt body and compares the signature byte for byte.
