# P1 independent schema consumer

This branch builds upon the prior P0 consumer PR without changing its existing inventory fixture or relying on `examples/sales.json` from the compiler repo.

It installs ProtocolIA pinned to [`8da92628798a`](https://github.com/barbasmarcosi/ProtocolIA/commit/8da92628798a659d4992747ca0faa3c588340865), fetches its JSON Schema by the **same immutable commit**, and checks the local inventory contract plus independent structural/semantic negative cases.

The tests establish compatibility for a limited test corpus only. They do not validate a generated server, runtime authorization, cost improvements or exhaustive grammar equivalence.

Keep the PR stacked onto `test/p0-independent-consumer` until the parent consumer PR is merged.
