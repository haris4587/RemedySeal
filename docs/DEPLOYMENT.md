# Deployment

Live deployment and finalized Full Consensus evidence will be recorded here after verification.

1. Import `contracts/remedy_seal.py` unchanged into https://studio.genlayer.com.
2. Select Full Consensus and the built-in account. Constructor has no parameters.
3. Deploy; wait for FINALIZED and SUCCESS.
4. Call `create_review` with `evidence/demo-package.json`; wait for finalization.
5. Call `evaluate(0)` under Full Consensus; wait for FINALIZED and SUCCESS.
6. Read `get_review(0)` from finalized state. Verify expected PARTIALLY_FIXED, ordered checks MISSING/SATISFIED, independent validator votes, manifest and decision hashes.
7. Compare exported deployed source byte-for-byte with the GitHub contract, record its SHA-256, and commit the final receipts and report without modifying the contract.
