# Domainry Audit

The source-owned Audit business module used by Domainry Runtime and other
Domainry modules. It borrows a host database pool, owns `_audit_events` and
`_audit_export_artifacts`, and can append mandatory evidence inside a host-owned
transaction.

The module follows the standard Domainry boundaries:

- `internal/domain/audit` owns event construction, export policy, and repository ports.
- `internal/application/audit` orchestrates append, query, lifecycle, and export use cases.
- `internal/adapter/auditsdk` adapts internal services to the public Audit SDK.
- `internal/assembly/module` owns embedded-module composition.
- `internal/infrastructure/persistence/database` owns Audit stores, migrations, and schema boundaries.
- `internal/infrastructure/persistence/{sqlite,mysql,postgres}` owns dialect profiles.
- root `module` is the stable, logic-free public facade used by hosts.

Audit SDK v1 currently defines embedded Module mode only. This repository does
not add placeholder SaaS assembly, HTTP transport, or an `audit-server` command;
those boundaries belong with a deployment-neutral SDK protocol when introduced.
