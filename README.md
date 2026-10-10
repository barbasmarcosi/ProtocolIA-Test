# ProtocolIA-Test

This is an **independent downstream consumer** of [ProtocolIA](https://github.com/barbasmarcosi/ProtocolIA). It is not the compiler and does not reuse ProtocolIA's `examples/sales.json` fixture.

## P0 reproducibility and contract checks

The `test/p0-independent-consumer` branch pins upstream ProtocolIA to commit [`788fe9d67cc3`](https://github.com/barbasmarcosi/ProtocolIA/commit/788fe9d67cc3d6e502482a7f8e0eb766ac46a881) and exercises an unrelated inventory scenario:

- GET `/system/health` — public and read-only.
- GET `/inventory` — capability-protected read.
- POST `/inventory` — capability-protected write.

The GitHub Actions consumer workflow installs the upstream package from the exact commit, tests schema/IR semantics and regeneration safety, validates OpenAPI with a separately installed validator, and typechecks emitted TypeScript with an independently installed TS compiler.

**This suite checks emitted contract artifacts, not an actual HTTP server or its authorization enforcement.** It does not use providers, production data or deployed services. Add new independent fixtures when implementing P1/P2; do not change held-out fixtures merely to make a failing compiler look correct.
