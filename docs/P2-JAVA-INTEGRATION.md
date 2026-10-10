# ProtocolIA P2 independent downstream acceptance

This repository owns its contract under contracts/transactional-inventory.json and its own HTTP black-box test assertions. It uses an immutable ProtocolIA commit, Java 21, Spring Boot and disposable PostgreSQL. This acceptance checks only the explicit bounded inventory-sale profile, not arbitrary domain rules or general-purpose program generation. No production migrations: Flyway is enabled only for an ephemeral CI database.
