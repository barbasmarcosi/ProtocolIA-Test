# ProtocolIA-Test

Independent consumer and adversarial integration-test repository for [ProtocolIA](https://github.com/barbasmarcosi/ProtocolIA).

This repository intentionally has its own fixtures and verification criteria. ProtocolIA is installed as a **pinned Git commit** rather than imported from local source. It does not deploy services, access secrets, or perform production writes.

Test cases are introduced via independent feature branches and pull requests. A green test validates a particular compiler commit and consumer fixture only; it does not prove application-level business correctness.
