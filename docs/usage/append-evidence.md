# When should a source owner append an Audit event?

## Problems solved

- Captures immutable actor-attributed evidence for committed business or administrative effects without making Audit decide or execute the change.

## Business scenarios

- An order approval records actor, operation, subject, outcome, reason, and correlation after the authoritative transaction commits.
- A privileged Role or provider configuration change records before/after evidence without copying secrets into Audit.
- A denied high-risk export records exact actor, permission/policy, target, outcome, and correlation even though no business write commits.

## Use when

Append Audit evidence when a committed effect, denied high-value attempt, security-sensitive configuration change, or subject-right transition must be attributable and reviewable.

## Do not use when

Do not append debug logs, metrics, transient retries, worker heartbeats,
cache-invalidation refresh delivery, connection lifecycle, uncommitted intent,
plaintext credentials, or full sensitive record payloads.

## How to use

Let the source owner decide the effect, choose the registered event family it
owns, append a typed event at the transaction boundary or durable outbox,
include the family's required metadata plus stable identities and safe
evidence, and use one idempotency/correlation identity across retries.

An event family is a contract, not a free-form label. Register it centrally in
the Audit SDK with an owner, Audit class, optional allowed event prefixes, and
required metadata keys. Do not create a module-specific audit/evidence table to
avoid that contract, and do not derive the family from event-name text at read
time. Unregistered families and incomplete required metadata are rejected
before persistence.

Keep lineage in the canonical fields. Set `operation_id` to the accepted shared
Operations receipt, `causation_id` to the upstream request or event that caused
the fact, and `owner_run_id` only when a distinct durable owner aggregate
exists. Audit inherits `operation_id` from Foundation's owner-execution context
when the append request does not set one; `causation_id` may come from the
authenticated actor. Do not duplicate these identities in metadata or use an
Operation receipt as a pretend owner run.

## Adaptation cookbook

| Evidence requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Record who approved an order | Registered business-action family plus Audit append | After the guarded approval commits, append actor, required Action key, order subject, outcome, reason, and correlation ID exactly once | Writing an “approved” event before the transaction succeeds |
| Record a denied privileged attempt | Denial Audit event | Capture principal, exact permission/policy, target identity, reason, and safe diagnostic metadata without the secret request body | Logging only an HTTP 403 line or copying tokens into evidence |
| Record a provider credential rotation | Administrative event with redacted before/after metadata | Record connection/key identities, actor, revision, and outcome; omit secret material | Storing old/new secret values in Audit |
| Diagnose CPU spikes | Monitoring metrics | Publish operational observations and time series | Flooding immutable Audit with health samples |

## Example

When `order.approve` commits, the order owner appends actor, Workspace, Object/record, exact Action, successful outcome, reason, version, and correlation at the correct commit/outbox boundary. A denied sensitive export appends denial evidence with the exact policy and safe target metadata even though no business write occurs. A transient retry, worker heartbeat, cache refresh delivery, stream connection, uncommitted intent, debug line, metric sample, plaintext token, or full sensitive payload is not an Audit event. Append authority belongs to the source owner/host; an ordinary user cannot manufacture authoritative evidence by calling a generic endpoint.

## Permissions and scope

Append authority belongs to trusted source services, not end users. Query/export authority is separate, and the event's Workspace/subject scope must remain explicit.

## Boundaries

The source owner owns the business decision and transaction. Audit owns immutable evidence, not rollback, current state, or operational telemetry.
