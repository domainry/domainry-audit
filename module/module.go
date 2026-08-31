// Package module is the stable public embedding boundary for Domainry hosts.
// Assembly implementation is internal so it cannot become a second business
// layer or be imported piecemeal by consumers.
package module

import (
	"context"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	moduleassembly "github.com/domainry/domainry-audit/internal/assembly/module"
)

type Options = moduleassembly.Options
type Factory = moduleassembly.Factory

func NewFactory(options Options) *Factory { return moduleassembly.NewFactory(options) }
func OwnedTables() []string               { return moduleassembly.OwnedTables() }
func SchemaMigrations(dialect modulehost.Dialect, driver string) ([]modulehost.SchemaMigration, error) {
	return moduleassembly.SchemaMigrations(dialect, driver)
}

func AppendPreparedWithin(ctx context.Context, dialect modulehost.Dialect, tx contract.Transaction, event contract.AuditEvent) error {
	return moduleassembly.AppendPreparedWithin(ctx, dialect, tx, event)
}
