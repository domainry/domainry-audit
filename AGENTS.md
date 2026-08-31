# Development rules

- Answer architecture and implementation questions from the current repository code and tests, not from memory.
- Every database has exactly one host-owned migration ledger named `_schema_migrations`. Audit must submit source-owned migrations through the host migration registrar and must not create its own migration ledger.
- Persistence DDL and DML must use `github.com/domainry/domainry-orm`. Raw SQL is allowed only when the ORM has no equivalent, with a local justification and dialect-focused tests.
- Audit uses the host database, transaction boundary, SQL dialect, migration lock, and migration ledger. Audit retains ownership of its business schema and migration definitions.
- Preserve the internal DDD layout: `internal/application/audit`, `internal/domain/audit/{repository,service}`, `internal/adapter/auditsdk`, `internal/assembly/module`, and `internal/infrastructure/persistence`.
- Keep the public `module` package a thin facade over `internal/assembly/module`; do not expose application, domain, persistence, or adapter implementations.
