# P3-B1 independent Docker conformance

This repository owns its own binary input fixture, request and host policy. Its CI installs ProtocolIA from the immutable commit 85f36acdd6bd1c35d884270147082a3cab26e323 and runs a real unprivileged Docker container against the fixture with network disabled and only its disposable staged file mounted read-only.

Tests: signed operator approval, one external execution, read-only result digest, replay without duplicate attempts, stale input, TTL expiration, revocation, simultaneous callers, shell denial, path traversal, symlink escape and unknown/paid budget denial.

No production credentials, production files or third-party services. The explicit operator in this test is a synthetic host-authorized test identity; this is not proof of a deployed human identity provider or a general-purpose external-agent sandbox.
