package persistence

import (
	"fmt"
	auditschema "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/schema"
	mysqlschema "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/schema/mysql"
	postgresschema "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/schema/postgres"
	sqliteschema "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/schema/sqlite"
	ormdialect "github.com/domainry/domainry-orm/dialect"
)

type Engine interface{ auditschema.Profile }

var engineFactories = map[ormdialect.Name]func() Engine{
	ormdialect.SQLite:   func() Engine { return sqliteschema.Profile{} },
	ormdialect.MySQL:    func() Engine { return mysqlschema.Profile{} },
	ormdialect.Postgres: func() Engine { return postgresschema.Profile{} },
}

func NewEngine(driver string) (Engine, error) {
	dialect, err := ormdialect.Parse(driver)
	if err != nil {
		return nil, fmt.Errorf("Audit database driver %q is unsupported: %w", driver, err)
	}
	factory := engineFactories[dialect.Name()]
	if factory == nil {
		return nil, fmt.Errorf("Audit database driver %q is unsupported", driver)
	}
	return factory(), nil
}
