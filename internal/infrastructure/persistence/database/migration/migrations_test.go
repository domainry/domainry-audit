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
			if len(migrations) != 3 || len(migrations[0].Statements)+len(migrations[1].Statements)+len(migrations[2].Statements) != 9 {
				t.Fatalf("migrations=%+v", migrations)
			}
			if migrations[0].Baseline == nil || len(migrations[0].Baseline.Tables) != 1 || migrations[1].Baseline != nil {
				t.Fatalf("migration baseline=%+v", migrations[0].Baseline)
			}
			joined := strings.Join(append(append(append([]string(nil), migrations[0].Statements...), migrations[1].Statements...), migrations[2].Statements...), "\n")
			for _, required := range []string{"_audit_events", "_audit_export_artifacts", "idx_audit_event_actor_cursor", "idx_audit_event_actor_org_cursor", "actor_org_id", "uniq_audit_export_idempotency"} {
				if !strings.Contains(joined, required) {
					t.Errorf("%s migration missing %q", driver, required)
				}
			}
		})
	}
}

func TestActorOrganizationScopeMigrationUpgradesExistingAuditSchemaInHostLedger(t *testing.T) {
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
	if err := runner.Apply(t.Context(), migrations[:2]); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `INSERT INTO _audit_events (id, workspace_id, event, metadata_json, before_json, after_json, created_at) VALUES ('legacy', 'workspace', 'order.updated', '{}', '{}', '{}', '2026-09-03T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := runner.Apply(t.Context(), migrations); err != nil {
		t.Fatal(err)
	}
	var actorOrgColumnCount int
	if err := database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('_audit_events') WHERE name = 'actor_org_id'`).Scan(&actorOrgColumnCount); err != nil || actorOrgColumnCount != 1 {
		t.Fatalf("actor organization column count=%d err=%v", actorOrgColumnCount, err)
	}
	var applied int
	if err := database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _schema_migrations`).Scan(&applied); err != nil || applied != 3 {
		t.Fatalf("host migration ledger count=%d err=%v", applied, err)
	}
}
