# RemedySeal submission package

Category: Builder → Intelligent Contracts

## Title

RemedySeal — Evidence-Bound Remediation Verification

## One-line description

GenLayer validator consensus checks whether a software patch fixes a locked vulnerability using version-pinned code and regression evidence.

## Notes / Description (946 characters)

RemedySeal is a reusable GenLayer Intelligent Contract for checking security remediations against locked vulnerability evidence and requirements. Validators independently retrieve commit-pinned issue, affected-code, patch and regression files, verify SHA-256 and byte lengths, and assess the same defect and patch linkage. Deterministic rules produce FIXED, PARTIALLY_FIXED, UNRESOLVED or INCONCLUSIVE, with exact source excerpts, bounded owner-only retries, sealed conclusive results and hash-linked receipts. Includes prompt-injection defenses, 38 passing adversarial tests, GenVM lint and SDK validation. A real Studio Full Consensus test finalized UNRESOLVED for a patch that retains a sibling-directory traversal bypass. Deployed source matches GitHub byte-for-byte. Finalized receipts, validator votes, source hash and earlier inconclusive attempts are documented. This verifies supplied technical evidence, not universal software security.

## Evidence

See [verified deployment](DEPLOYMENT.md) for all contract, deployment, review-creation and Full Consensus transaction URLs, the exact source commit, SHA-256, decision hash and observed votes.

Repository: https://github.com/haris4587/RemedySeal

Final source: https://github.com/haris4587/RemedySeal/blob/2e9ff35cad93b31ed43716ae17c07f57c4d330ad/contracts/remedy_seal.py

Tests: https://github.com/haris4587/RemedySeal/blob/main/evidence/offline-tests.txt

GenVM checks: https://github.com/haris4587/RemedySeal/blob/main/evidence/genvm-validation.txt

Finalized review: https://github.com/haris4587/RemedySeal/blob/main/evidence/finalized-review.json

Security: https://github.com/haris4587/RemedySeal/blob/main/docs/SECURITY.md

Deployment report: https://github.com/haris4587/RemedySeal/blob/main/docs/DEPLOYMENT.md

Evidence manifest: https://github.com/haris4587/RemedySeal/blob/main/evidence/demo-package.json
