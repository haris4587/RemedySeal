# Evidence and receipts

Package JSON uses exactly `title`, `requirements` (ordered strings), and `sources` (ordered vulnerability, affected, patch, regression). Each source has exactly `role`, `url`, `sha256`, `bytes`. Use complete relevant patched code, not just an isolated diff that hides unchanged vulnerable paths. Pin genuine release/version metadata and test execution provenance when it matters. The included demo deliberately uses a small, fully inspectable synthetic example.

`evidence/demo-package.json` locks the public fixture commit after it is pushed. Requirements independently ask for relative sibling traversal protection and absolute-path protection, so the partial fix has an unambiguous ordered result: MISSING, SATISFIED.

`evidence/regression.py` runs the real partial patch: normal nested reads work, absolute input is rejected, and relative sibling traversal still returns a synthetic secret. These are counterexample assertions, not a passing claim that the patch closes the issue. Full Consensus should independently inspect this evidence and identify partial remediation.

Hash algorithm: SHA-256 over exact UTF-8 bytes. Canonical JSON is Python `json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True)`. Package hash covers canonical package. Decision hash covers the entire record before adding its `decision_hash` field, including quoted evidence and the previous decision hash. `scripts/verify_receipt.py` verifies manifests, package hash and the complete attempt chain from an exported `get_review` JSON object. An offline receipt proves internal consistency, not on-chain inclusion; pair it with finalized transaction/source records.
