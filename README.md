# Domainry Audit

The source-owned Audit business module used by Domainry Runtime and other
Domainry modules. It borrows a host database pool, owns `_audit_events` and
`_audit_export_artifacts`, and can append mandatory evidence inside a host-owned
transaction.

The module follows the standard Domainry boundaries:

- `internal/domain/audit` owns event construction, export policy, repository ports, and product-surface scope/retention/pagination/redaction rules.
- `internal/application/audit` orchestrates append, query, lifecycle, and export use cases.
- `internal/adapter/auditsdk` adapts internal services to the public Audit SDK.
- `internal/assembly/module` owns embedded-module composition.
- `internal/infrastructure/persistence/database` owns Audit stores, migrations, and schema boundaries.
- `internal/infrastructure/persistence/{sqlite,mysql,postgres}` owns dialect profiles.
- `internal/transport/http/module` owns Audit product HTTP routes and OpenAPI operations exposed through Foundation `modulehttp`.
- root `module` is the stable, logic-free public facade used by hosts.

Audit SDK v1 currently defines embedded Module mode only. The Module Binding
publishes its product HTTP Surface after the host supplies the narrow
cross-owner record access and field-projection capabilities. This repository
does not add placeholder SaaS assembly or an `audit-server` command; those
boundaries require a deployment-neutral remote protocol first.
