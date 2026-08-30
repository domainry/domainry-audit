# Domainry Audit

The source-owned Audit business module used by Domainry Runtime and other
Domainry modules. It borrows a host database pool, owns `_audit_events` and
`_audit_export_artifacts`, and can append mandatory evidence inside a host-owned
transaction.

The module follows the standard Domainry boundaries:

- `internal/domain` owns event construction and domain policy.
- `internal/application` orchestrates append, query, lifecycle, and export use cases.
- `internal/infrastructure` owns host-database persistence and schema installation.
- `internal/module` owns embedded-module assembly.
- root `module` is the stable, logic-free public facade used by hosts.
