package schema

import (
	"fmt"

	"github.com/domainry/domainry-audit-sdk/modulehost"
	ormbuilder "github.com/domainry/domainry-orm/builder"
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
	eventTable, _, err := ormbuilder.NewCreateTableBuilder(renderer, "_audit_events").WithoutSystemColumns().Columns(auditColumns()...).PrimaryKey("workspace_id", "id").Build()
	if err != nil {
		return nil, fmt.Errorf("build Audit table _audit_events: %w", err)
	}
	exportTable, _, err := ormbuilder.NewCreateTableBuilder(renderer, "audit_export_artifacts").WithoutSystemColumns().Columns(exportColumns()...).PrimaryKey("workspace_id", "id").Build()
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
		builder := ormbuilder.NewCreateIndexBuilder(renderer, index.name, index.table).Columns(index.columns...)
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

func auditColumns() []ormbuilder.SchemaColumn {
	return []ormbuilder.SchemaColumn{
		required("id", ormbuilder.TextKeyType(191)), required("workspace_id", ormbuilder.TextKeyType(191)), required("event", ormbuilder.TextKeyType(191)),
		ormbuilder.DefineColumn("object_key", ormbuilder.TextKeyType(191)), ormbuilder.DefineColumn("record_id", ormbuilder.TextKeyType(191)),
		ormbuilder.DefineColumn("actor_id", ormbuilder.TextKeyType(191)), ormbuilder.DefineColumn("role_key", ormbuilder.TextKeyType(191)), ormbuilder.DefineColumn("summary", ormbuilder.LongTextType()),
		required("metadata_json", ormbuilder.JSONType()), required("before_json", ormbuilder.JSONType()), required("after_json", ormbuilder.JSONType()), required("created_at", ormbuilder.TextKeyType(40)),
	}
}

func exportColumns() []ormbuilder.SchemaColumn {
	return []ormbuilder.SchemaColumn{
		required("workspace_id", ormbuilder.TextKeyType(191)), required("id", ormbuilder.TextKeyType(191)), required("requester_user_id", ormbuilder.TextKeyType(191)),
		required("role_key", ormbuilder.TextKeyType(191)), required("idempotency_key", ormbuilder.TextKeyType(191)), required("filters_json", ormbuilder.JSONType()),
		required("scope_sha256", ormbuilder.TextKeyType(64)), required("authorization_scope_sha256", ormbuilder.TextKeyType(64)), required("token_sha256", ormbuilder.TextKeyType(64)),
		required("filename", ormbuilder.LongTextType()), required("content_sha256", ormbuilder.TextKeyType(64)), required("row_count", ormbuilder.BigIntType()), required("content_base64", ormbuilder.LongTextType()),
		required("audit_identity", ormbuilder.LongTextType()), required("status", ormbuilder.TextKeyType(32)), required("created_at", ormbuilder.TextKeyType(40)), required("expires_at", ormbuilder.TextKeyType(40)),
		ormbuilder.DefineColumn("download_count", ormbuilder.BigIntType()).NotNull().DefaultValue(0), required("last_downloaded_at", ormbuilder.TextKeyType(40)),
	}
}

func required(name string, kind ormbuilder.ColumnType) ormbuilder.SchemaColumn {
	return ormbuilder.DefineColumn(name, kind).NotNull()
}
