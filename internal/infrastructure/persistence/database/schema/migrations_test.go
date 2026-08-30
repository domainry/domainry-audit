package schema_test

import (
	"strings"
	"testing"

	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	ormdialect "github.com/domainry/domainry-orm/dialect"
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
			if len(migrations) != 2 || len(migrations[0].Statements)+len(migrations[1].Statements) != 7 {
				t.Fatalf("migrations=%+v", migrations)
			}
			if migrations[0].Baseline == nil || len(migrations[0].Baseline.Tables) != 1 || migrations[1].Baseline != nil {
				t.Fatalf("migration baseline=%+v", migrations[0].Baseline)
			}
			joined := strings.Join(append(append([]string(nil), migrations[0].Statements...), migrations[1].Statements...), "\n")
			for _, required := range []string{"_audit_events", "audit_export_artifacts", "idx_audit_event_actor_cursor", "uniq_audit_export_idempotency"} {
				if !strings.Contains(joined, required) {
					t.Errorf("%s migration missing %q", driver, required)
				}
			}
		})
	}
}
