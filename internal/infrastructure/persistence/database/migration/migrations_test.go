package migration_test

import (
	"database/sql"
	"strings"
	"testing"

	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormmigration "github.com/domainry/domainry-orm/migration"
	_ "modernc.org/sqlite"
)

func TestMigrationsRenderThroughSupportedORMProfiles(t *testing.T) {
	for _, driver := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			renderer, err := ormdialect.ParseRenderer(driver, "audit_scope", "")
			if err != nil {
				t.Fatal(err)
			}
			migrations, err := auditpersistence.SchemaMigrations(renderer, driver)
			if err != nil {
				t.Fatal(err)
			}
			if len(migrations) != 2 || len(migrations[0].Statements)+len(migrations[1].Statements) != 8 {
				t.Fatalf("migrations=%+v", migrations)
			}
			if migrations[0].Baseline == nil || len(migrations[0].Baseline.Tables) != 1 || migrations[1].Baseline != nil {
				t.Fatalf("migration baseline=%+v", migrations[0].Baseline)
			}
			joined := strings.Join(append(append([]string(nil), migrations[0].Statements...), migrations[1].Statements...), "\n")
			for _, required := range []string{"_audit_events", "idx_audit_event_cursor", "idx_audit_event_actor_cursor", "idx_audit_event_actor_org_cursor", "idx_audit_event_record_cursor", "idx_audit_event_operation_cursor", "idx_audit_event_causation_cursor", "idx_audit_event_owner_run_cursor", "actor_org_id", "operation_id", "causation_id", "owner_run_id"} {
				if !strings.Contains(joined, required) {
					t.Errorf("%s migration missing %q", driver, required)
				}
			}
			for _, retired := range []string{"_audit_export_artifacts", "content_base64", "uniq_audit_export_idempotency"} {
				if strings.Contains(joined, retired) {
					t.Errorf("%s migration retained %q", driver, retired)
				}
			}
		})
	}
}

func TestFinalAuditSchemaInstallsScopeAndCursorIndexesDirectly(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	renderer, err := ormdialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := auditpersistence.SchemaMigrations(renderer, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := ormmigration.NewRunner(database, renderer, ormmigration.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Apply(t.Context(), migrations); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"actor_org_id", "operation_id", "causation_id", "owner_run_id"} {
		var columnCount int
		if err := database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('_audit_events') WHERE name = ?`, name).Scan(&columnCount); err != nil || columnCount != 1 {
			t.Fatalf("column %s count=%d err=%v", name, columnCount, err)
		}
	}
	for name, want := range map[string]string{
		"idx_audit_event_cursor":           "workspace_id,created_at,id",
		"idx_audit_event_actor_cursor":     "workspace_id,actor_id,created_at,id",
		"idx_audit_event_actor_org_cursor": "workspace_id,actor_org_id,created_at,id",
		"idx_audit_event_record_cursor":    "workspace_id,object_key,record_id,created_at,id",
		"idx_audit_event_operation_cursor": "workspace_id,operation_id,created_at,id",
		"idx_audit_event_causation_cursor": "workspace_id,causation_id,created_at,id",
		"idx_audit_event_owner_run_cursor": "workspace_id,owner_run_id,created_at,id",
	} {
		rows, err := database.QueryContext(t.Context(), `SELECT name FROM pragma_index_info(?) ORDER BY seqno`, name)
		if err != nil {
			t.Fatal(err)
		}
		columns := []string{}
		for rows.Next() {
			var column string
			if err := rows.Scan(&column); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			columns = append(columns, column)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(columns, ","); got != want {
			t.Fatalf("index %s columns=%q want=%q", name, got, want)
		}
	}
	var applied int
	if err := database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _schema_migrations`).Scan(&applied); err != nil || applied != 2 {
		t.Fatalf("host migration ledger count=%d err=%v", applied, err)
	}
}
