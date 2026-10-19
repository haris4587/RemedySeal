# Security model

## What is authenticated

The allowlisted HTTPS origin is raw.githubusercontent.com; every path includes a full lowercase 40-hex Git object ID. SHA-256 and exact bytes bind content. Affected/patch/regression paths must use one repository. Sources are fetched independently per validator; HTTP 200, length, digest and UTF-8 decoding must all succeed before an LLM sees content. A digest authenticates a submitter's commitment, not the submitter's authority, the adviser's reputation, or the completeness/truth of supplied evidence. Repository ownership, real release inclusion and execution provenance still need evidence and reviewer judgment.

## Consensus

Independent validators rerun the semantic assessment. Every ordered requirement status, baseline flag, linkage flag, verdict and failure reason must match exactly. The validator checks leader quotes against independently authenticated bytes and recomputes the deterministic aggregate. Different valid wording/excerpt choices are allowed. A leader's assertion or JSON formatting alone never establishes correctness. Missing/contradictory evidence maps conservatively to INCONCLUSIVE. Consensus disagreement fails the transaction rather than storing a manufactured majority fallback.

## Injection and bounds

All user and repository text is labeled untrusted data in the fixed prompt; embedded commands cannot change the parser, evidence hashes, status enum, citation checks or aggregation. Prompt-injection resistance remains a probabilistic LLM property, not a guarantee. Exact quotations prove presence, not relevance; semantic relevance requires honest independent validators. No supplied code is executed by the contract, and no evidence links are followed by the prompt.

Packages <=16,000 UTF-8 bytes; 1–6 distinct requirements <=600 characters; title <=160 characters; exactly four source files, each <=18,000 bytes and total <=48,000 bytes; URL <=500 characters; bounded quotes (12–500 characters, 1–8 per citation set); three attempts maximum. The web module may allocate a response before its post-fetch length check; underlying HTTP resource limits still apply. The model service may charge or consume resources before output is validated.

## State and permissions

Anyone may create an independent request; only its creator can evaluate it. Immutable requirements and source manifests cannot be swapped by the sponsor. A conclusive assessment is immutable. INCONCLUSIVE attempts stay visible, are hash-linked, and allow two retries of the same locked package. Failed transactions do not create partial history. Domain, contract address, creator, review ID, attempt, package hash and prior decision hash bind each decision. Chain/network scope should accompany receipts externally; the contract hash alone is not a cross-chain identity.

## Limitations

No bounty, escrow, automated exploit runner or security certification. Supplied evidence can omit important components. Checks are only as complete as locked requirements. FIXED means supported within those requirements and evidence; it does not promise that a release is vulnerability-free. Runtime-sensitive claims need credible pinned execution artifacts. A source's disappearance can exhaust bounded retries; create a separate review with new evidence rather than editing history. Studio is a hosted sandbox; Full Consensus there is not mainnet economic security. Do not submit unpublished sensitive vulnerability material to public GitHub or public contract state.
