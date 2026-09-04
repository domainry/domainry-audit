# Domainry Audit

The source-owned Audit business module used by Domainry Runtime and other
Domainry modules. It borrows a host database pool, owns `_audit_events` and
`_audit_export_artifacts`, and can append mandatory evidence inside a host-owned
transaction.

The module follows the standard Domainry boundaries:

- `internal/domain/audit` owns event construction, export policy, repository ports, and product-adapter scope/retention/pagination/redaction rules.
- `internal/application/audit` orchestrates append, query, lifecycle, and export use cases.
- `internal/adapter/auditsdk` adapts internal services to the public Audit SDK.
- `internal/assembly/module` owns embedded-module composition.
- `internal/infrastructure/persistence/database` owns Audit stores, migrations, and schema boundaries.
- `internal/infrastructure/persistence/{sqlite,mysql,postgres}` owns dialect profiles.
- `internal/transport/http/module` owns Audit product HTTP routes and OpenAPI operations exposed through Foundation `modulehttp`.
- root `module` is the stable, logic-free public facade used by hosts.

Audit SDK v1 currently defines embedded Module mode only. The Module Binding
publishes its product HTTP Adapter after the host supplies the narrow
cross-owner record access and field-projection capabilities. This repository
does not add placeholder SaaS assembly or an `audit-server` command; those
boundaries require a deployment-neutral remote protocol first.

## Data authorization

Every product route requires its own exact Permission function grant and the
data policy for that same key. Audit translates only `all`, `owner`, `org`,
`org_child`, and `target_org`, then passes the resolved boundary explicitly to
its repositories. `all` adds no range predicate; every other scope is applied
inside the workspace-scoped SQL query.

Audit events use `actor_id` as their natural owner. Organization visibility is
based on the event-time `actor_org_id` snapshot supplied in event metadata and
projected into the Audit table; rows without that evidence fail closed for
organization scopes. Export artifacts remain requester-owned through
`requester_user_id`; because they have no reliable organization fact,
organization-only artifact access fails closed instead of consulting mutable
directory state.

The SDK `Reader`, `ExportStore`, append, and subject-lifecycle ports are trusted
module-integration capabilities rather than end-user authorization adapters.
Product HTTP requests must use the scoped application services assembled after
`BindApplicationHost`.

## Continuous integration

The GitHub Actions workflow runs with `GOWORK=off`, so it verifies the versions
locked by this repository instead of silently borrowing sibling checkouts. The
repository or organization must provide a read-only `DOMAINRY_READ_TOKEN`
secret that can clone the private `github.com/domainry/*` Go modules.
