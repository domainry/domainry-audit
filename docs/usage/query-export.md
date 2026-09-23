# How should authorized users query or export audit history?

## Problems solved

- Enables authorized investigation and evidence delivery without exposing an unrestricted event store or rebuilding history from logs.

## Business scenarios

- Exporting all customer-change evidence for a regulator-defined date range.
- Reviewing one subject's lifecycle history or one administrator's privileged actions during an incident.
- Applying Lifecycle retention, legal-hold, and permitted subject-identifier anonymization without deleting evidence as if it were an ordinary Record.
- Separating immutable actor history from Monitoring's current state and Report's business analytics.

## Use when

Use bounded query/export for compliance review by actor, subject, source owner, action, and time range.

## Do not use when

Do not use Audit as a general report engine or unrestricted event lake.

## How to use

Require explicit filters, stable paging, hard limits, and separate export preparation/retrieval. Apply Lifecycle retention and legal holds before subject erasure or evidence deletion.

## Adaptation cookbook

| Review requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Compliance reviews customer changes for one month. | Scoped Audit query and export | Filter by authorized Workspace, subject/action, and date range; export actor, action, subject, timestamp, and evidence metadata. | Reading the raw event store or exporting all Workspaces. |
| Investigate one administrator's privileged activity. | Actor-scoped Audit query | Use exact review permission and bounded filters, then retain export/download evidence if a file is produced. | Querying current business tables and assuming their state explains the history. |
| Show a product revenue trend. | Report | Define governed measures and dimensions in Report. | Treating business analytics as Audit history. |
| Subject erasure reaches retained compliance evidence | Lifecycle-governed retention/anonymization | Keep legally required event facts and integrity chain, anonymize only identifiers allowed by policy, and record the owner outcome | Deleting Audit rows as ordinary business records or claiming complete erasure while held evidence remains |

## Example

To answer “who changed customer `c-42`?”, a compliance Role queries one Workspace with subject `customer/c-42`, time range, source owner, Action, and stable cursor; the review permission constrains every page. A large compliance export freezes those filters and produces an Artifact with query identity, integrity evidence, requester, and download audit. Subject Lifecycle may retain or permittedly anonymize identifiers under policy, but Audit is never directly deleted as a normal Record. Audit answers historical attribution; Monitoring answers current health; Report answers business measures.

## Permissions and scope

`audit.query` and `audit.export` are independent. A reviewer’s data scope must constrain both the online rows and the exported artifact.

## Boundaries

Lifecycle owns retention/hold coordination; Data Exchange may own large artifact transfer. Audit remains authoritative for immutable events.
