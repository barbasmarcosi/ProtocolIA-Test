# P3 external action-plan consumer

This repository owns its own warehouse task and host policy; both differ from upstream's examples. CI installs the immutable ProtocolIA commit ef5475e59989abb4845c1f1244810bd3c5fad9e6. The host policy includes a bounded evidence freshness window and the suite proves that evidence older than that window cannot be reused. Both Python 3.11 and 3.13 run a real CLI-to-SQLite sequence and independently inspect results.

Safety checks: denied resources and unauthorized effects before any journal opens; rejects shell tool, path traversal, forged capability, budget overflow, stale environment or mutated state, cancellation and duplicate effect replays.

This is a provider-free local SQLite execution experiment. It is not OS isolation, a network tool sandbox, production authentication, external side-effect compensation, or evidence of cost savings. The consumer deliberately does not control or alter the compiler's own example or expected test fixtures.
