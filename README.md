# Domainry Audit

Product Agent question index: [`capability/agent/index.json`](capability/agent/index.json). Ordinary mutation evidence is appended automatically by Runtime and is intentionally absent from product Agent routing; the remaining guide covers only an explicit audit-history or evidence-export product requirement.

The source-owned Audit business module used by Domainry Runtime and other
Domainry modules. It borrows a host database pool, owns only `_audit_events`,
and can append mandatory evidence inside a host-owned transaction. Audit export
CSV bytes live in deployment blob storage; owner `audit`, kind `export`
metadata and requester bindings live in shared `_artifacts` and
`_artifact_bindings`. Every successful prepare also completes one owner
`audit`, kind `audit.export.prepare` receipt in the host's shared
`_operations` ledger; its redacted result references the Artifact, and the
Artifact carries an Operation binding. Export is advertised only when the host
supplies both shared Operation and Artifact ports. Audit creates no private
export table and stores no base64 payload in SQL.

`_audit_events` is the single cross-module evidence table. Every appended row
stores an SDK-registered `family`; each registration declares its owning source,
Audit class, allowed event-name prefixes when the family is constrained, and
required metadata keys. Append fails before SQL when a family is unknown or its
required metadata is absent. Query class filtering resolves to registered family
keys, so Audit does not infer governance or operations meaning from arbitrary
event-name substrings.

The final schema installs scope-aware cursor indexes directly: Workspace
timeline, actor timeline, actor-organization timeline, and Object/record
timeline all end in `created_at, id` for stable pagination. `actor_org_id` is
part of the initial table definition; there is no upgrade-only add-column path.

Cross-store lineage is stored in typed nullable columns, not hidden in
`metadata_json`: `operation_id` links the accepted shared Operations receipt,
`causation_id` links the upstream request/event that caused the fact, and
`owner_run_id` links a durable owner aggregate such as a Workflow execution,
Lifecycle cleanup job or subject request. Each identity has a
Workspace-scoped `created_at, id` cursor index and an exact query filter.
Callers must not label an Operation receipt as an owner run merely because both
are execution-shaped identifiers.

Lifecycle compliance transitions, Identity profile-binding history,
authentication/security decisions, module HTTP operator denials and Runtime
break-glass changes all append to this table with registered source-owned
families. The retired `_lifecycle_audit_evidence` and
`_identity_profile_binding_events` tables have no production readers or
writers. Break-glass state stores the actual deterministic Audit event ID and
fails into its existing compensation path if the Audit append fails.

Automated retry attempts, worker heartbeats, cache-invalidation refresh
publication and refresh-stream connection lifecycle are operational telemetry,
not immutable Audit facts. Their owners retain attempt/lease state and publish
bounded counters instead. A human or operator command that deliberately starts
a retry remains an attributable administrative fact; the worker attempts that
follow it do not become one Audit row per attempt.

Normal Audit persistence is append-only. An exact idempotent replay succeeds
only when the complete stored evidence matches; a changed payload never updates
the original row. Retention deletion is restricted to Lifecycle policy
`audit.evidence.v1`: expired evidence is archived before purge, and active legal
holds skip the matching rows. Subject-rights processing may anonymize permitted
identifiers and sensitive projections without deleting the event identity.

The module follows the standard Domainry boundaries:

- `internal/domain/audit` owns event construction, export policy, repository ports, and product-adapter scope/retention/pagination/redaction rules.
- `internal/application/audit` orchestrates append, query, lifecycle, and export use cases.
- `internal/adapter/auditsdk` adapts internal services to the public Audit SDK.
- `internal/assembly/module` owns embedded-module composition.
- `internal/infrastructure/persistence/database` owns Audit stores, migrations, and schema boundaries.
- `internal/infrastructure/persistence/{sqlite,mysql,postgres}` owns dialect profiles.
- `internal/transport/http/module` owns Audit product HTTP routes and typed operations exposed through Foundation `modulehttp`; current SDK source and contract tests are the exact public contract.
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
