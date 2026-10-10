# P3 external action-plan consumer

This repository owns its own warehouse task and host policy; both differ from upstream's examples. CI installs the immutable ProtocolIA commit cf5c532cfd638cfc2b60073582cbcd4d3173fbaa. Both Python 3.11 and 3.13 run a real CLI-to-SQLite sequence and independently inspect results.

Safety checks: denied resources and unauthorized effects before any journal opens; rejects shell tool, path traversal, forged capability, budget overflow, stale environment or mutated state, cancellation and duplicate effect replays.

This is a provider-free local SQLite execution experiment. It is not OS isolation, a network tool sandbox, production authentication, external side-effect compensation, or evidence of cost savings. The consumer deliberately does not control or alter the compiler's own example or expected test fixtures.
