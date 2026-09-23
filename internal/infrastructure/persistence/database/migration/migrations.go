package migration

import (
	"fmt"

	"github.com/domainry/domainry-foundation/schemaownership"
	ormschema "github.com/domainry/domainry-orm/schema"

	"github.com/domainry/domainry-audit-sdk/modulehost"
)

const (
	MigrationOwner  = "audit"
	EventsTableName = "_audit_events"
)

type ColumnKind string

const (
	Key191 ColumnKind = "key191"
	Key64  ColumnKind = "key64"
	Key40  ColumnKind = "key40"
	Key32  ColumnKind = "key32"
	Long   ColumnKind = "long"
	JSON   ColumnKind = "json"
	BigInt ColumnKind = "bigint"
)

type Profile interface {
	ColumnType(ColumnKind) (string, error)
}

func Migrations(renderer modulehost.Dialect, profile Profile) ([]modulehost.SchemaMigration, error) {
	if profile == nil {
		return nil, fmt.Errorf("Audit database engine is required")
	}
	eventTable, _, err := ormschema.NewTable(renderer, EventsTableName).Columns(auditColumns()...).PrimaryKey("workspace_id", "id").Build()
	if err != nil {
		return nil, fmt.Errorf("build Audit table %s: %w", EventsTableName, err)
	}
	indexStatements := []string{}
	indexes := []struct {
		table, name string
		unique      bool
		columns     []string
	}{
		{EventsTableName, "idx_audit_event_cursor", false, []string{"workspace_id", "created_at", "id"}},
		{EventsTableName, "idx_audit_event_actor_cursor", false, []string{"workspace_id", "actor_id", "created_at", "id"}},
		{EventsTableName, "idx_audit_event_actor_org_cursor", false, []string{"workspace_id", "actor_org_id", "created_at", "id"}},
		{EventsTableName, "idx_audit_event_record_cursor", false, []string{"workspace_id", "object_key", "record_id", "created_at", "id"}},
		{EventsTableName, "idx_audit_event_operation_cursor", false, []string{"workspace_id", "operation_id", "created_at", "id"}},
		{EventsTableName, "idx_audit_event_causation_cursor", false, []string{"workspace_id", "causation_id", "created_at", "id"}},
		{EventsTableName, "idx_audit_event_owner_run_cursor", false, []string{"workspace_id", "owner_run_id", "created_at", "id"}},
	}
	for _, index := range indexes {
		columns := index.columns
		if adapter, ok := profile.(interface {
			IndexColumns(string, []string) []string
		}); ok && !index.unique {
			columns = adapter.IndexColumns(index.table, columns)
		}
		builder := ormschema.NewIndex(renderer, index.name, index.table).Columns(columns...)
		if index.unique {
			builder.Unique()
		}
		statement, _, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("build Audit index %s: %w", index.name, err)
		}
		indexStatements = append(indexStatements, statement)
	}
	baseline, err := schemaBaseline(profile)
	if err != nil {
		return nil, err
	}
	return []modulehost.SchemaMigration{
		{Version: 1, Name: "audit_events", Statements: []string{eventTable}, Baseline: &baseline},
		{Version: 2, Name: "audit_indexes", Statements: indexStatements},
	}, nil
}

func SchemaOwnership() []schemaownership.Table {
	return []schemaownership.Table{{
		Name: EventsTableName, Owner: MigrationOwner, WorkspaceScope: schemaownership.ScopeWorkspace,
		RetentionClass: schemaownership.RetentionLegalAudit, PrimaryKey: []string{"workspace_id", "id"},
		BoundedQueryPath: "workspace cursor and actor, organization, record, operation, causation or owner-run cursors enforce a maximum page size",
		DeletionPolicy:   "append-only event identity is retained; typed subject erasure anonymizes personal projections atomically, while policy-governed archival and purge must respect legal holds",
	}}
}

func OwnedTables() []string { return schemaownership.Names(SchemaOwnership()) }

func schemaBaseline(profile Profile) (modulehost.SchemaBaseline, error) {
	specs := []struct {
		name              string
		kind              ColumnKind
		nullable, primary bool
	}{
		{"id", Key191, false, true}, {"workspace_id", Key191, false, true}, {"family", Key191, false, false}, {"event", Key191, false, false},
		{"object_key", Key191, true, false}, {"record_id", Key191, true, false}, {"actor_id", Key191, true, false}, {"actor_org_id", Key191, true, false},
		{"operation_id", Key191, true, false}, {"causation_id", Key191, true, false}, {"owner_run_id", Key191, true, false},
		{"role_key", Key191, true, false}, {"summary", Long, true, false}, {"metadata_json", JSON, false, false},
		{"before_json", JSON, false, false}, {"after_json", JSON, false, false}, {"created_at", Key40, false, false},
	}
	events := modulehost.SchemaTable{Name: EventsTableName, Columns: make([]modulehost.SchemaColumn, len(specs))}
	for index, spec := range specs {
		physical, err := profile.ColumnType(spec.kind)
		if err != nil {
			return modulehost.SchemaBaseline{}, fmt.Errorf("resolve Audit baseline column %s: %w", spec.name, err)
		}
		events.Columns[index] = modulehost.SchemaColumn{Name: spec.name, Type: physical, Nullable: spec.nullable, PrimaryKey: spec.primary}
	}
	return modulehost.SchemaBaseline{Tables: []modulehost.SchemaTable{events}}, nil
}

func auditColumns() []ormschema.ColumnDefinition {
	return []ormschema.ColumnDefinition{
		required("id", ormschema.TextKey(191)), required("workspace_id", ormschema.TextKey(191)), required("family", ormschema.TextKey(191)), required("event", ormschema.TextKey(191)),
		ormschema.Column("object_key", ormschema.TextKey(191)), ormschema.Column("record_id", ormschema.TextKey(191)),
		ormschema.Column("actor_id", ormschema.TextKey(191)), ormschema.Column("actor_org_id", ormschema.TextKey(191)),
		ormschema.Column("operation_id", ormschema.TextKey(191)), ormschema.Column("causation_id", ormschema.TextKey(191)), ormschema.Column("owner_run_id", ormschema.TextKey(191)),
		ormschema.Column("role_key", ormschema.TextKey(191)), ormschema.Column("summary", ormschema.LongText()),
		required("metadata_json", ormschema.JSON()), required("before_json", ormschema.JSON()), required("after_json", ormschema.JSON()), required("created_at", ormschema.TextKey(40)),
	}
}

func required(name string, kind ormschema.ColumnType) ormschema.ColumnDefinition {
	return ormschema.Column(name, kind).NotNull()
}
