package persistence

import (
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditmigration "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/migration"
)

func SchemaMigrations(renderer modulehost.Dialect, driver string) ([]modulehost.SchemaMigration, error) {
	engine, err := NewEngine(driver)
	if err != nil {
		return nil, err
	}
	return auditmigration.Migrations(renderer, engine)
}
