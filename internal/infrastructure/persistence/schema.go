package persistence

import (
	"github.com/domainry/domainry-audit-sdk/modulehost"
	storeschema "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/schema"
)

func SchemaMigrations(renderer modulehost.Dialect, driver string) ([]modulehost.SchemaMigration, error) {
	return storeschema.Migrations(renderer, driver)
}
