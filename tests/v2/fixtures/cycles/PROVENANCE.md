# Cycles test fixtures provenance

Copied byte for byte from the TypeScript SDK, `agent-passport-system/agent-passport-system`
at commit `ababe0ffc8a1383ccc00691fde6289bc1bd2e70a` (`ababe0f`). Nothing in this
repository edits them.

| here | upstream path |
|---|---|
| `fixtures/02-reserve-allow.json` | `tests/v2/payment-rails/cycles-fixtures/02-reserve-allow.json` |
| `fixtures/03-reserve-dry-run-deny.json` | `tests/v2/payment-rails/cycles-fixtures/03-reserve-dry-run-deny.json` |
| `fixtures/11-reserve-live-budget-exceeded.json` | `tests/v2/payment-rails/cycles-fixtures/11-reserve-live-budget-exceeded.json` |
| `fixtures/12-decide-live-forbidden.json` | `tests/v2/payment-rails/cycles-fixtures/12-decide-live-forbidden.json` |
| `evidence-vectors/05-commit-success.json` | `tests/v2/payment-rails/cycles-evidence-vectors/05-commit-success.json` |
| `evidence-vectors/06-release-success.json` | `tests/v2/payment-rails/cycles-evidence-vectors/06-release-success.json` |

They are CyclesEvidence envelopes signed by the Cycles server. Fixtures 03, 11
and 12 are the denial mapping goldens.
