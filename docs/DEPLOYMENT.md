# Verified Studio deployment — 2026-10-19

## Final deployment

| Field | Verified value |
|---|---|
| Network | Hosted Studionet / GenLayer Studio sandbox |
| Mode | Normal (Full Consensus), simulation checkbox off |
| Built-in account | `0x0a6a54B9e0fd10eD8E258a5955b26710f58D389f` |
| Contract | `0x350E2780656d22D67089e10A3ACE4f811cF987b7` |
| Source commit | `2e9ff35cad93b31ed43716ae17c07f57c4d330ad` |
| Source SHA-256 | `5d7dbbba2978878aa7113ba6dc455324f7f7f9f372fe97ff58eb8ee904a08d49` |
| Source bytes | 12,231 |
| Deployment | `0xac3ac0b26d5d428534abd758db607fe94c657db55e602794281173909962921a` — FINALIZED, SUCCESS |
| Create review | `0x5e8d73aa61e3aca769bcce4a56925fdb2b321f5c952ab812b7c78bef099dad14` — FINALIZED, SUCCESS |
| Full Consensus evaluate(0) | `0x009957a7874623e5f8f23a91a922cfb8e9ebaffbc6c2b20bb49fcdfa1b163dd8` — FINALIZED, SUCCESS |
| Finalized verdict | **UNRESOLVED**, baseline/linkage true, checks `[MISSING, MISSING]` |
| Decision hash | `26829716154f1269dd4e6eb1897d433072bf9a416dcc98f967f6a3a5b8caa2ee` |
| Package hash | `5401cb6e4e346d9a5bb3283a2132ed138353ba5a6b6a3597f9285fdc895ce9f8` |

Deployment was finalized before the final test. Evaluation finalized at Oct 19, 2026, 16:35:12 Asia/Colombo. Studio's read-state selector was explicitly switched to **Finalized** before `get_review(0)` was called. Both the Explorer equivalence output and the finalized read showed UNRESOLVED. The Explorer Code tab returned exactly 12,231 UTF-8 bytes and the SHA-256 above, matching the pushed GitHub source.

Explorer displayed five initial participants and one leader rotation. Final votes displayed **3 agree, 1 disagree, 1 idle**. This was not unanimous. The accepted execution succeeded with no stdout/stderr. Full Consensus is the Studio sandbox's consensus pipeline, not a mainnet deployment or production-security certification.

## Meaningful test and interpretation

The synthetic patch adds an absolute-path guard but retains string-prefix containment. The actual executable fixture proves that a relative sibling-directory traversal still reads outside the intended directory. The live acceptance criterion was to reject the patch as a complete fix and produce an evidence-supported conclusive result. It did: **UNRESOLVED**.

The preliminary expectation was PARTIALLY_FIXED because the local absolute-path check passes. The live strict root-cause assessment instead marked both requirements MISSING. The exact vector is preserved rather than relabeled. This demonstrates that semantic consensus can be conservative and requirement wording affects the assessment; the result is not a proof of perfect per-requirement classification. Offline mocked status tests verify aggregation, authorization and evidence handling, not model accuracy.

## Evidence links

- [Contract / source](https://explorer-studio.genlayer.com/address/0x350E2780656d22D67089e10A3ACE4f811cF987b7)
- [Deployment receipt](https://explorer-studio.genlayer.com/tx/0xac3ac0b26d5d428534abd758db607fe94c657db55e602794281173909962921a)
- [Review creation](https://explorer-studio.genlayer.com/tx/0x5e8d73aa61e3aca769bcce4a56925fdb2b321f5c952ab812b7c78bef099dad14)
- [Full Consensus receipt, outputs and votes](https://explorer-studio.genlayer.com/tx/0x009957a7874623e5f8f23a91a922cfb8e9ebaffbc6c2b20bb49fcdfa1b163dd8)
- [Final source commit](https://github.com/haris4587/RemedySeal/commit/2e9ff35cad93b31ed43716ae17c07f57c4d330ad)
- [Exact finalized read](../evidence/finalized-review.json)
- [Machine-readable deployment record](../evidence/deployment.json)
- [Finalized Explorer screenshot](../evidence/final-consensus.jpg)
- [Offline tests](../evidence/offline-tests.txt)
- [GenVM validation](../evidence/genvm-validation.txt)

The evidence-only commit containing this report does not alter the deployed contract. Obtain its exact final commit with `git rev-parse HEAD` after pulling main; the completion message also records that commit.

## Transparent earlier attempts

The initial deployment at `0xe4ed5818a5441918a3dAd452eDb06936345d490b` is **superseded**. Its first Full Consensus evaluation and bounded retry returned INCONCLUSIVE / INVALID_ASSESSMENT. The first finalized receipt and original source are retained in `evidence/initial/`. The improved source lets models select numbered source lines; deterministic code resolves them into exact excerpts, reducing brittle whitespace reproduction. Six additional tests verify that path and reject malformed line references.

- [Initial deployment](https://explorer-studio.genlayer.com/tx/0x4a9bd0e8435919acc2d567b54125139b71333e367a61d2c53108498b099567e8)
- [Initial inconclusive evaluation](https://explorer-studio.genlayer.com/tx/0x70c6859ffff60db5893cd8e47d574d93b0290b9bec84872f86a8db80288d38d7)
- [Inconclusive retry](https://explorer-studio.genlayer.com/tx/0x73d1afc2ed633cd331c9593cf44a657c029f3d15272dc19f24db5d7c22c85b8a)

## Reproduce and verify

Import the exact final source from the source commit into Studio, retain Normal (Full Consensus), deploy using the built-in account, call create_review with `evidence/demo-package.json`, then evaluate the returned review ID. Do not retry the sealed conclusive review on the recorded deployment. For a new independent assessment create a new review ID.

```sh
python scripts/verify_receipt.py evidence/finalized-review.json evidence
python evidence/regression.py
```

Verify FINALIZED and SUCCESS separately. The offline verifier checks internal hashes and source files, not RPC inclusion; verify inclusion using the Explorer receipts above.
