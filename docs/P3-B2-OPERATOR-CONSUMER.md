# Independent ProtocolIA operator authentication verification

The downstream consumer owns its own binary warehouse input, separate v0.5 read-only DAG, synthetic operator enrollment, Ed25519 private keys generated **only inside ephemeral GitHub CI**, separate protected host signing key and live Docker invocation. It pins ProtocolIA source `2e0a71b57a0a1b28ab04dda27314852436cb9039`.

A subprocess simulates the operator's offline signing CLI, requiring explicit plan SHA and resource confirmation, while the verifier owns only registered public keys. It refuses an unrelated private signer, expired/stale permissions, changed file, altered plan and revoked operator key. It also proves rotation requires a new enrolled public key and a new immutable plan request. No production credentials, registered humans, paid calls or external write permissions are used.

This is a **cryptographic possession proof and fail-closed host gateway**, not evidence of a deployed authenticator app, OIDC login, MFA factor, network/TLS security or WebAuthn-backed human identity.
