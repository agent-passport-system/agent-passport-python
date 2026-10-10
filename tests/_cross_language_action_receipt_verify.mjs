// Read JSON {receipt, publicKey} from stdin and verify via the TS SDK's legacy verifyReceipt.
// Called from tests/test_action_receipt_cross_language.py.

import { verifyReceipt } from '../../agent-passport-system/src/core/delegation.js'

let raw = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => { raw += chunk })
process.stdin.on('end', () => {
  try {
    const { receipt, publicKey } = JSON.parse(raw)
    process.stdout.write(JSON.stringify(verifyReceipt(receipt, publicKey)))
  } catch (e) {
    process.stdout.write(`ERROR:${e?.message || String(e)}`)
    process.exit(1)
  }
})
