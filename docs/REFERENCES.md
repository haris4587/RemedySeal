# Official references checked 2026-10-19

- https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle — independent validation, not formatting-only validation.
- https://docs.genlayer.com/developers/intelligent-contracts/features/calling-llms — structured JSON and custom run_nondet_unsafe validator.
- https://docs.genlayer.com/developers/intelligent-contracts/features/storage — TreeMap and persistent state.
- https://docs.genlayer.com/api-references/genlayer-linter — lint and SDK semantic validation.
- https://docs.genlayer.com/developers/intelligent-contracts/testing — direct tests versus multi-validator Studio execution.
- https://docs.genlayer.com/developers/intelligent-contracts/tools/genlayer-studio — hosted environment and limitations.

Compatibility was verified against Studio's displayed v0.2.16 dependency header and the matching official GenVM release SDK. Its `genlayer/gl/nondet/web.py` defines `Response.status`, `Response.body` and `web.get`; use `status`, not obsolete/inconsistent `status_code` examples. Runner hash is explicit in the first two contract lines.
