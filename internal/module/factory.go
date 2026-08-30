package module

import (
	"context"
	"fmt"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	exportapp "github.com/domainry/domainry-audit/internal/application/export"
	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	auditstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/audit"
	exportstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/export"
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
	exportService := exportapp.NewService(auditService, exports, auditService, f.options.Clock)
	return &binding{audit: auditService, exports: exportService, exportStore: exports}, nil
}

type binding struct {
	audit       *auditapp.Service
	exports     *exportapp.Service
	exportStore *exportstore.Store
}

func (b *binding) Descriptor() auditsdk.Descriptor {
	return auditsdk.Descriptor{ProtocolVersion: auditsdk.ProtocolVersionV1, Mode: auditsdk.DeploymentModeModule, Capabilities: auditsdk.Capabilities{TransactionalAppend: true, Query: true, SubjectLifecycle: true}}
}
func (b *binding) Factory() contract.EventFactory                        { return b.audit }
func (b *binding) Appender() contract.Appender                           { return b.audit }
func (b *binding) TransactionalAppender() contract.TransactionalAppender { return b.audit }
func (b *binding) PreparedAppender() contract.PreparedAppender           { return b.audit }
func (b *binding) Reader() contract.Reader                               { return b.audit }
func (b *binding) SubjectLifecycle() contract.SubjectLifecycle           { return b.audit }
func (b *binding) ExportStore() contract.ExportStore                     { return b.exportStore }
func (b *binding) Exporter() contract.Exporter                           { return b.exports }
func (b *binding) Close(context.Context) error                           { return nil }

var _ auditsdk.Factory = (*Factory)(nil)
