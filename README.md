# RemedySeal

A standalone GenLayer Intelligent Contract that checks whether a proposed software remediation closes a **locked, evidence-bound vulnerability**. No frontend or external wallet is required: deploy and call from GenLayer Studio's built-in account.

## Useful primitive

Create an immutable review containing requirements and exactly four evidence roles: vulnerability report, affected code, complete patched code, and regression evidence. Each source uses a full Git commit URL, SHA-256 and exact byte length. Every validator independently retrieves the files, verifies bytes, establishes the defect/patch relationship, and evaluates each requirement. The equivalence rule requires exact agreement on baseline, linkage and the entire ordered requirement-status vector, while allowing different valid supporting excerpts.

| Outcome | Deterministic rule |
|---|---|
| FIXED | Confirmed baseline/linkage; every requirement SATISFIED |
| PARTIALLY_FIXED | Confirmed baseline/linkage; mixture of SATISFIED and MISSING |
| UNRESOLVED | Confirmed baseline/linkage; every requirement MISSING |
| INCONCLUSIVE | Unknown requirement, unconfirmed baseline/linkage, unavailable/changed evidence or invalid model output |

Model-selected numbered lines are resolved deterministically into exact excerpts. Positive closure requires exact quotations from both patched code and regression evidence. Validators also revalidate the leader's exact excerpts and reject forged results. This is semantic evidence assessment, **not execution of untrusted code or proof of universal security**.

## Contract interface

- `create_review(package_json) -> int`: validate and permanently lock package; creator becomes review owner.
- `evaluate(review_id)`: owner only. First conclusive result seals the review; at most three attempts following INCONCLUSIVE results, with no evidence replacement.
- `get_review(review_id) -> str`: canonical JSON package, hash, owner and append-only hash-linked attempts.
- `get_count() -> int`: number of independent requests.

A review has no global participation slots, deposits, transfers or admin override. One request cannot block another. Amendments require a new review ID. Protocol finality is separate from a stored assessment: verify transaction FINALIZED and execution SUCCESS before relying on reads.

## Reproduce

Python 3.12+:

```sh
python -m pip install -r requirements-dev.txt
GENVM_VERSION=v0.2.16 genvm-lint check contracts/remedy_seal.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p gltest.direct.pytest_plugin -q tests --disable-warnings
python evidence/regression.py
```

Direct-mode tests use the actual pinned SDK with mocked web/LLM I/O; they are not live consensus. The regression fixture executes locally in a temporary directory, showing an absolute-path fix with a surviving sibling-prefix bypass. Its intentionally vulnerable files are demo inputs, never production utilities.

## Review materials

- [Security model and limits](docs/SECURITY.md)
- [Deployment and live test](docs/DEPLOYMENT.md)
- [Evidence format and verification](docs/EVIDENCE.md)
- [Official documentation used](docs/REFERENCES.md)
- [Contract ABI](docs/abi.json)

MIT licensed. Original synthetic demo; no undisclosed real vulnerability is published.
