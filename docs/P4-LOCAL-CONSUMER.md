# P4 independent local CLI simulation

This ProtocolIA-Test-only acceptance test pins upstream ProtocolIA runner commit 80a0129b4535a508b0ead969e53467c67ff72270 and the actual independently published held-out judge commit 77ec9150fed3b1ae4e80c87befc052e34702af8c.

A fake Codex subprocess exits 0 and reports positive input/output token counters but writes NO Java application. The real HTTP grader then evaluates a closed localhost port and MUST return a FAIL verdict. This is recorded as one failure, not a success, keeping 35 other tasks missing and the winner unknown. It also rejects a replayed run identifier and a modified task specification. No Codex/Claude Code subscription is used, no APIs/keys are required, and zero model cost reduction is claimed.

The benchmark runner is NOT an OS sandbox. Its separate directories and only-local grading do not prevent an untrusted same-UID process from reading files unless the operator supplies actual VM/container restrictions. Real experiments still require subscribed CLIs installed and logged in by the user on a trusted machine.
