# `action-receipt-v1.1-vectors.json`, provenance

Vendored byte for byte from the TypeScript SDK. Nothing in this repository
generates or edits it. A change to its bytes belongs upstream.

| field | value |
|---|---|
| source repository | `agent-passport-system/agent-passport-system` (TypeScript SDK) |
| source path | `fixtures/action-receipt-v1.1/action-receipt-vectors-v1.1.json` |
| SDK merge commit | `949d77dd32024391192556e248ec9a25d863f8fe`, merge of #217, the commit that carries the vector file |
| generator reference commit | `c31d94aad86713ae9b2e4cbc811deeab4b5d91ed`, also written inside the JSON at `sdk_reference.commit` |
| SHA-256 of the file as vendored | `2452c818e916f516d238c756fea913228a2a6e28696f86aae4b85776ee8938a3` |

`tests/test_action_receipt_cross_language.py` asserts that SHA-256 against the
file on disk.

To re-fetch the exact bytes:

```
git -C <agent-passport-system> show 949d77dd32024391192556e248ec9a25d863f8fe:fixtures/action-receipt-v1.1/action-receipt-vectors-v1.1.json
```
