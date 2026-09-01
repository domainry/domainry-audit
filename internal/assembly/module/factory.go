// Package module assembles the in-process Audit implementation over host-owned
// infrastructure.
package module

import (
	"context"
	"fmt"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditcapability "github.com/domainry/domainry-audit/capability"
	auditsdkadapter "github.com/domainry/domainry-audit/internal/adapter/auditsdk"
	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	auditstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/audit"
	exportstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/export"
	audithttp "github.com/domainry/domainry-audit/internal/transport/http/module"
	"github.com/domainry/domainry-foundation/modulehttp"
)

type Options struct{ Clock contractClock }
type contractClock interface{ Now() time.Time }

type Factory struct{ options Options }

func OwnedTables() []string {
	return []string{"_audit_events", "_audit_export_artifacts"}
}

func SchemaMigrations(dialect modulehost.Dialect, driver string) ([]modulehost.SchemaMigration, error) {
	return auditpersistence.SchemaMigrations(dialect, driver)
}

func NewFactory(options Options) *Factory { return &Factory{options: options} }

func (f *Factory) OpenModule(ctx context.Context, application auditsdk.ApplicationRef, host modulehost.Host) (auditsdk.Binding, error) {
	if host == nil || host.Database() == nil || host.Dialect() == nil || host.Migrations() == nil {
		return nil, fmt.Errorf("Audit Module host is incomplete")
	}
	migrations, err := auditpersistence.SchemaMigrations(host.Dialect(), host.Migrations().Driver())
	if err != nil {
		return nil, err
	}
	if err := host.Migrations().ApplyOwnedMigrations(ctx, "audit", migrations); err != nil {
		return nil, fmt.Errorf("apply Audit Module migrations: %w", err)
	}
	return f.open(ctx, application, host.Database(), host.Dialect())
}

func (f *Factory) open(ctx context.Context, application auditsdk.ApplicationRef, database modulehost.Database, renderer modulehost.Dialect) (auditsdk.Binding, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("audit context unavailable")
	}
	if err := application.Validate(); err != nil {
		return nil, err
	}
	events := auditstore.NewStore(database, renderer)
	auditService := auditapp.NewService(events, f.options.Clock)
	exports := exportstore.NewStore(database, renderer)
	exportService := auditapp.NewExportService(auditService, exports, auditService, f.options.Clock)
	capability, err := auditcapability.Open(auditcapability.Inputs{})
	if err != nil {
		return nil, fmt.Errorf("build Audit capability disclosure: %w", err)
	}
	binding, err := auditsdkadapter.NewBinding(auditService, exportService, exports, capability)
	if err != nil {
		return nil, err
	}
	binding.SetApplicationHostBinder(func(host modulehost.AuditApplicationHost) ([]modulehttp.Surface, error) {
		application, err := auditapp.NewAuditSurfaceApplicationService(auditService, exportService, host, f.options.Clock)
		if err != nil {
			return nil, err
		}
		surface, err := audithttp.NewAuditSurface(application)
		if err != nil {
			return nil, err
		}
		return []modulehttp.Surface{surface}, nil
	})
	return binding, nil
}

var _ auditsdk.Factory = (*Factory)(nil)
