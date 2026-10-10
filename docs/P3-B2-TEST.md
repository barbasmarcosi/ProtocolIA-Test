# Independent P3-B2.1 typed broker consumer

The ProtocolIA-Test repo owns a distinct binary receipts fixture, a distinct versioned DAG, an external host policy and independent acceptance assertions. GitHub CI pins ProtocolIA upstream SHA 67c87ad998936215e7a6c7d10d56645908afa21a and executes an actual Docker read-only image.

Tests include concurrent same-request execution without duplicate Docker effect, HMAC-approved plan hash binding, stale request/policy/input refusal, typed DAG postcondition, unknown-cost hard refusal, forged revocation key and revoked host permission. This tests **only one read-only external operation**. No paid providers, arbitrary agent shells, production identities or write compensation are supported or claimed.
