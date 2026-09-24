package migration_test

import (
	"database/sql"
	"slices"
	"strings"
	"testing"

	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	"github.com/domainry/domainry-foundation/schemaownership"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormmigration "github.com/domainry/domainry-orm/migration"
	_ "modernc.org/sqlite"
)

func TestSchemaOwnershipMatchesEveryFreshAuditTableAndPrimaryKey(t *testing.T) {
	tables := auditpersistence.SchemaOwnership()
	if err := schemaownership.ValidateAll(tables); err != nil {
		t.Fatal(err)
	}
	renderer, err := ormdialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := auditpersistence.SchemaMigrations(renderer, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	created := map[string]string{}
	for _, migration := range migrations {
		for _, statement := range migration.Statements {
			const prefix = `CREATE TABLE "`
			if !strings.HasPrefix(statement, prefix) {
				continue
			}
			name, _, found := strings.Cut(strings.TrimPrefix(statement, prefix), `"`)
			if !found || name == "" {
				t.Fatalf("invalid CREATE TABLE statement: %s", statement)
			}
			created[name] = statement
		}
	}
	if len(created) != len(tables) || !slices.Equal(auditpersistence.OwnedTables(), schemaownership.Names(tables)) {
		t.Fatalf("fresh Audit tables=%v ownership=%+v", created, tables)
	}
	for _, table := range tables {
		statement, found := created[table.Name]
		if !found {
			t.Fatalf("Audit table %s has ownership but no canonical DDL", table.Name)
		}
		quoted := make([]string, len(table.PrimaryKey))
		for index, column := range table.PrimaryKey {
			quoted[index] = `"` + column + `"`
		}
		if primaryKey := "PRIMARY KEY (" + strings.Join(quoted, ", ") + ")"; !strings.Contains(statement, primaryKey) {
			t.Fatalf("Audit table %s ownership primary key %v does not match DDL: %s", table.Name, table.PrimaryKey, statement)
		}
	}
}

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
			wantMigrations, wantStatements := 2, 8
			if driver == "mysql" {
				wantMigrations, wantStatements = 3, 9
			}
			statementCount := 0
			for _, migration := range migrations {
				statementCount += len(migration.Statements)
			}
			if len(migrations) != wantMigrations || statementCount != wantStatements {
				t.Fatalf("migrations=%+v", migrations)
			}
			if migrations[0].Baseline == nil || len(migrations[0].Baseline.Tables) != 1 || migrations[1].Baseline != nil {
				t.Fatalf("migration baseline=%+v", migrations[0].Baseline)
			}
			statements := []string{}
			for _, migration := range migrations {
				statements = append(statements, migration.Statements...)
			}
			joined := strings.Join(statements, "\n")
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
			if driver == "mysql" {
				if strings.Contains(migrations[0].Statements[0], "CHARACTER SET ascii") {
					t.Fatal("published MySQL Audit migration 1 was edited")
				}
				if got := migrations[0].Baseline.Tables[0].Columns[0].Type; got != "VARCHAR(191)" {
					t.Fatalf("published MySQL Audit migration 1 baseline id type=%q", got)
				}
				for _, column := range []string{"`id` VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL", "`created_at` VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL"} {
					if !strings.Contains(migrations[2].Statements[0], column) {
						t.Errorf("MySQL Audit migration omitted binary cursor column %q", column)
					}
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
