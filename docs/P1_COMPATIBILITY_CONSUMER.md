# P1 consumer compatibility diff

A distinct inventory contract (not the upstream Sales example) exercises additive optional fields, breaking required-field additions, capability changes, effect ordering and CLI breaking exit status.

Upstream source and v0.1 schema are fetched from the same immutable commit `9fe1e5ef262cbee263882e089929367ad237fbb6`; the consumer's existing OpenAPI and TypeScript verification remains enabled.

This is a smoke/regression test of a **conservative syntactic change classifier**, not evidence of deploy-time runtime compatibility. The PR remains stacked on `test/p1-independent-schema` pending parent merge.
