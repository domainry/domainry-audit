package persistence

import (
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditmigration "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/migration"
	"github.com/domainry/domainry-foundation/schemaownership"
)

const MigrationOwner = auditmigration.MigrationOwner

func SchemaMigrations(renderer modulehost.Dialect, driver string) ([]modulehost.SchemaMigration, error) {
	engine, err := NewEngine(driver)
	if err != nil {
		return nil, err
	}
	return auditmigration.Migrations(renderer, engine)
}

func SchemaOwnership() []schemaownership.Table { return auditmigration.SchemaOwnership() }

func OwnedTables() []string { return auditmigration.OwnedTables() }
