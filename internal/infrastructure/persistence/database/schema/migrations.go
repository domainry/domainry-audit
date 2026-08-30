package schema

import (
	"fmt"
	"strings"

	"github.com/domainry/domainry-audit-sdk/modulehost"
	ormbuilder "github.com/domainry/domainry-orm/builder"
)

func Migrations(renderer modulehost.Dialect, driver string) ([]modulehost.SchemaMigration, error) {
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
	baseline, err := schemaBaseline(driver)
	if err != nil {
		return nil, err
	}
	return []modulehost.SchemaMigration{
		{Version: 1, Name: "audit_events", Statements: []string{eventTable}, Baseline: &baseline},
		{Version: 2, Name: "audit_exports_and_indexes", Statements: exportStatements},
	}, nil
}

func schemaBaseline(driver string) (modulehost.SchemaBaseline, error) {
	types := map[string]string{}
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "sqlite", "sqlite3":
		types = map[string]string{"key191": "TEXT", "key64": "TEXT", "key40": "TEXT", "key32": "TEXT", "long": "TEXT", "json": "TEXT", "bigint": "BIGINT"}
	case "postgres", "postgresql", "pgx":
		types = map[string]string{"key191": "TEXT", "key64": "TEXT", "key40": "TEXT", "key32": "TEXT", "long": "TEXT", "json": "JSONB", "bigint": "BIGINT"}
	case "mysql":
		types = map[string]string{"key191": "VARCHAR(191)", "key64": "VARCHAR(64)", "key40": "VARCHAR(40)", "key32": "VARCHAR(32)", "long": "LONGTEXT", "json": "JSON", "bigint": "BIGINT"}
	default:
		return modulehost.SchemaBaseline{}, fmt.Errorf("unsupported Audit database driver %q", driver)
	}
	column := func(name, kind string, nullable, primary bool) modulehost.SchemaColumn {
		return modulehost.SchemaColumn{Name: name, Type: types[kind], Nullable: nullable, PrimaryKey: primary}
	}
	events := modulehost.SchemaTable{Name: "_audit_events", Columns: []modulehost.SchemaColumn{
		column("id", "key191", false, true), column("workspace_id", "key191", false, true), column("event", "key191", false, false),
		column("object_key", "key191", true, false), column("record_id", "key191", true, false), column("actor_id", "key191", true, false),
		column("role_key", "key191", true, false), column("summary", "long", true, false), column("metadata_json", "json", false, false),
		column("before_json", "json", false, false), column("after_json", "json", false, false), column("created_at", "key40", false, false),
	}}
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
