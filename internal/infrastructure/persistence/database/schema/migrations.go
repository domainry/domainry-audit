package schema

import (
	"fmt"
	ormschema "github.com/domainry/domainry-orm/schema"

	"github.com/domainry/domainry-audit-sdk/modulehost"
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
	eventTable, _, err := ormschema.NewTable(renderer, "_audit_events").Columns(auditColumns()...).PrimaryKey("workspace_id", "id").Build()
	if err != nil {
		return nil, fmt.Errorf("build Audit table _audit_events: %w", err)
	}
	exportTable, _, err := ormschema.NewTable(renderer, "audit_export_artifacts").Columns(exportColumns()...).PrimaryKey("workspace_id", "id").Build()
	if err != nil {
		return nil, fmt.Errorf("build Audit table audit_export_artifacts: %w", err)
	}
	exportStatements := []string{exportTable}
	indexes := []struct {
		table, name string
		unique      bool
		columns     []string
	}{
		{"_audit_events", "idx_audit_event_actor_cursor", false, []string{"workspace_id", "actor_id", "created_at", "id"}},
		{"_audit_events", "idx_audit_event_record_cursor", false, []string{"workspace_id", "object_key", "record_id", "created_at", "id"}},
		{"audit_export_artifacts", "uniq_audit_export_idempotency", true, []string{"workspace_id", "requester_user_id", "idempotency_key"}},
		{"audit_export_artifacts", "uniq_audit_export_token_hash", true, []string{"workspace_id", "token_sha256"}},
		{"audit_export_artifacts", "idx_audit_export_expiry", false, []string{"workspace_id", "expires_at"}},
	}
	for _, index := range indexes {
		builder := ormschema.NewIndex(renderer, index.name, index.table).Columns(index.columns...)
		if index.unique {
			builder.Unique()
		}
		statement, _, err := builder.Build()
		if err != nil {
			return nil, fmt.Errorf("build Audit index %s: %w", index.name, err)
		}
		exportStatements = append(exportStatements, statement)
	}
	baseline, err := schemaBaseline(profile)
	if err != nil {
		return nil, err
	}
	return []modulehost.SchemaMigration{
		{Version: 1, Name: "audit_events", Statements: []string{eventTable}, Baseline: &baseline},
		{Version: 2, Name: "audit_exports_and_indexes", Statements: exportStatements},
	}, nil
}

func schemaBaseline(profile Profile) (modulehost.SchemaBaseline, error) {
	specs := []struct {
		name              string
		kind              ColumnKind
		nullable, primary bool
	}{
		{"id", Key191, false, true}, {"workspace_id", Key191, false, true}, {"event", Key191, false, false},
		{"object_key", Key191, true, false}, {"record_id", Key191, true, false}, {"actor_id", Key191, true, false},
		{"role_key", Key191, true, false}, {"summary", Long, true, false}, {"metadata_json", JSON, false, false},
		{"before_json", JSON, false, false}, {"after_json", JSON, false, false}, {"created_at", Key40, false, false},
	}
	events := modulehost.SchemaTable{Name: "_audit_events", Columns: make([]modulehost.SchemaColumn, len(specs))}
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
		required("id", ormschema.TextKey(191)), required("workspace_id", ormschema.TextKey(191)), required("event", ormschema.TextKey(191)),
		ormschema.Column("object_key", ormschema.TextKey(191)), ormschema.Column("record_id", ormschema.TextKey(191)),
		ormschema.Column("actor_id", ormschema.TextKey(191)), ormschema.Column("role_key", ormschema.TextKey(191)), ormschema.Column("summary", ormschema.LongText()),
		required("metadata_json", ormschema.JSON()), required("before_json", ormschema.JSON()), required("after_json", ormschema.JSON()), required("created_at", ormschema.TextKey(40)),
	}
}

func exportColumns() []ormschema.ColumnDefinition {
	return []ormschema.ColumnDefinition{
		required("workspace_id", ormschema.TextKey(191)), required("id", ormschema.TextKey(191)), required("requester_user_id", ormschema.TextKey(191)),
		required("role_key", ormschema.TextKey(191)), required("idempotency_key", ormschema.TextKey(191)), required("filters_json", ormschema.JSON()),
		required("scope_sha256", ormschema.TextKey(64)), required("authorization_scope_sha256", ormschema.TextKey(64)), required("token_sha256", ormschema.TextKey(64)),
		required("filename", ormschema.LongText()), required("content_sha256", ormschema.TextKey(64)), required("row_count", ormschema.BigInt()), required("content_base64", ormschema.LongText()),
		required("audit_identity", ormschema.LongText()), required("status", ormschema.TextKey(32)), required("created_at", ormschema.TextKey(40)), required("expires_at", ormschema.TextKey(40)),
		ormschema.Column("download_count", ormschema.BigInt()).NotNull().DefaultValue(0), required("last_downloaded_at", ormschema.TextKey(40)),
	}
}

func required(name string, kind ormschema.ColumnType) ormschema.ColumnDefinition {
	return ormschema.Column(name, kind).NotNull()
}
