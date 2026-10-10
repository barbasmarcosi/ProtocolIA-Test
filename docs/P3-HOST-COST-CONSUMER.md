# Independent P3 host-approval service and cost ledger acceptance

The external ProtocolIA-Test repo owns a distinct binary receipt, v0.5 typed DAG, operator key (generated inside ephemeral CI), trusted host policies and signed metering receipts. A separately running Unix service authenticates requests using Linux peer UID and an offline Ed25519 signer subprocess, then executes one bounded read in actual Docker.

Positive assertions: valid signed grant, idempotent replay, correct digest and no duplicate effect. Negative assertions: forged signature, injection of host key path, altered plan/input, revoked operator key and denied peer UID. The test separately creates signed host-only micro-USD quotes and challenges the SQLite ledger with six concurrent reservations under a 10 micro-USD budget, ensures at most three 3-micro-USD reservations, and rejects unsigned/unknown cost. A trusted signed usage receipt settles a started reservation where the concurrency winner is available.

The test deliberately does not pay any provider or modify production files. It does not establish true human enrollment, SSO/MFA, kernel-escape resistance, paid-provider reconciliation, or multi-effect write compensation. Those still block full P3 issue #4 completion.
