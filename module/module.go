// Package module is the stable public embedding boundary for Domainry hosts.
// Assembly implementation is internal so it cannot become a second business
// layer or be imported piecemeal by consumers.
package module

import (
	"context"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	internalmodule "github.com/domainry/domainry-audit/internal/module"
)

type Options = internalmodule.Options
type Factory = internalmodule.Factory

func NewFactory(options Options) *Factory { return internalmodule.NewFactory(options) }
func OwnedTables() []string               { return internalmodule.OwnedTables() }
func SchemaMigrations(dialect modulehost.Dialect, driver string) ([]modulehost.SchemaMigration, error) {
	return internalmodule.SchemaMigrations(dialect, driver)
}

func AppendPreparedWithin(ctx context.Context, dialect modulehost.Dialect, tx contract.Transaction, event contract.AuditEvent) error {
	return internalmodule.AppendPreparedWithin(ctx, dialect, tx, event)
}
