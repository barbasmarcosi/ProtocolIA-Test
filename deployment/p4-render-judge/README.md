# ProtocolIA-Test P4 isolated independent judge on Render

This branch descends from **the immutable P4 verifier revision** `77ec9150fed3b1ae4e80c87befc052e34702af8c`.
`tools/p4_verify.py` is **unchanged**; its Git blob is `2e61191acce8af8b6290413946ffa5a73b239553`.

This is operator-controlled infrastructure, never shared with the B/C/A agent. It runs an independent 127.0.0.1 proxy forwarding to the pinned HTTPS candidate, waits for candidate health, and executes the unmodified frozen grader once. It exports sanitized `/verdict` as temporary public JSON and retains SHA256 in logs.

Special restrictions: the B candidate was generated in a **ChatGPT Work top-level session**, not authenticated Codex CLI; model/version/time/tokens unknown. B therefore is **unmatched exploratory**, not a preregistered Codex B run. Maven test compilation FAILED; runtime packaging/launch requires evaluator-only workarounds. An HTTP verdict is separate from build viability and experiment eligibility.

Render free service is publicly exposed, can spin down, and shares included instance hours. Delete the service once evidence has been recorded; do not expose credentials or production data. Do not change `tools/p4_verify.py`, P4 study, candidate workspace or other arms.
