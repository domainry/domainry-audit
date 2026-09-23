// Package module assembles the in-process Audit implementation over host-owned
// infrastructure.
package module

import (
	"context"
	"fmt"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditsdkadapter "github.com/domainry/domainry-audit/internal/adapter/auditsdk"
	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	auditstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/audit"
	exportstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/export"
	audithttp "github.com/domainry/domainry-audit/internal/transport/http/module"
	"github.com/domainry/domainry-foundation/modulehttp"
	sharedoperation "github.com/domainry/domainry-foundation/operation"
)

type Options struct{ Clock contractClock }
type contractClock interface{ Now() time.Time }

type Factory struct{ options Options }

func OwnedTables() []string {
	return []string{"_audit_events"}
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
	return f.open(ctx, application, host)
}

func (f *Factory) open(ctx context.Context, application auditsdk.ApplicationRef, host modulehost.Host) (auditsdk.Binding, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("audit context unavailable")
	}
	if err := application.Validate(); err != nil {
		return nil, err
	}
	events := auditstore.NewStore(host.Database(), host.Dialect())
	auditService := auditapp.NewService(events, f.options.Clock)
	operations, err := sharedoperation.Open(ctx, host.Database(), host.Dialect(), host.Migrations())
	if err != nil {
		return nil, fmt.Errorf("open Audit Operations persistence: %w", err)
	}
	var artifacts modulehost.ArtifactHost
	if available, ok := host.(modulehost.ArtifactHost); ok && available.ArtifactStore() != nil && available.ArtifactContentStore() != nil && available.ArtifactContentWriter() != nil {
		artifacts = available
	}
	exportReady := artifacts != nil
	var exports *exportstore.Store
	if exportReady {
		exports = exportstore.NewStore(artifacts.ArtifactStore(), artifacts.ArtifactContentStore(), artifacts.ArtifactContentWriter(), operations)
	} else {
		exports = exportstore.NewStore(nil, nil, nil, nil)
	}
	exportService := auditapp.NewExportService(auditService, exports, auditService, f.options.Clock)
	binding, err := auditsdkadapter.NewBinding(auditService, exportService, exports, exportReady, audithttp.AuthorizationActions(exportReady))
	if err != nil {
		return nil, err
	}
	binding.SetApplicationHostBinder(func(host modulehost.AuditApplicationHost) ([]modulehttp.Adapter, error) {
		application, err := auditapp.NewAuditQueryApplicationService(auditService, exportService, host, f.options.Clock)
		if err != nil {
			return nil, err
		}
		adapter, err := audithttp.NewAuditHTTPAdapter(application, exportReady)
		if err != nil {
			return nil, err
		}
		return []modulehttp.Adapter{adapter}, nil
	})
	return binding, nil
}

var _ auditsdk.Factory = (*Factory)(nil)
