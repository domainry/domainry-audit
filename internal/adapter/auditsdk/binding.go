// Package auditsdk adapts Audit application services to the public SDK.
package auditsdk

import (
	"context"

	sdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/contract"
	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	exportstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/export"
)

type Binding struct {
	audit       *auditapp.Service
	exports     *auditapp.ExportService
	exportStore *exportstore.Store
}

func NewBinding(audit *auditapp.Service, exports *auditapp.ExportService, exportStore *exportstore.Store) *Binding {
	return &Binding{audit: audit, exports: exports, exportStore: exportStore}
}

func (b *Binding) Descriptor() sdk.Descriptor {
	return sdk.Descriptor{ProtocolVersion: sdk.ProtocolVersionV1, Mode: sdk.DeploymentModeModule, Capabilities: sdk.Capabilities{TransactionalAppend: true, Query: true, SubjectLifecycle: true}}
}
func (b *Binding) Factory() contract.EventFactory                        { return b.audit }
func (b *Binding) Appender() contract.Appender                           { return b.audit }
func (b *Binding) TransactionalAppender() contract.TransactionalAppender { return b.audit }
func (b *Binding) PreparedAppender() contract.PreparedAppender           { return b.audit }
func (b *Binding) Reader() contract.Reader                               { return b.audit }
func (b *Binding) SubjectLifecycle() contract.SubjectLifecycle           { return b.audit }
func (b *Binding) ExportStore() contract.ExportStore                     { return b.exportStore }
func (b *Binding) Exporter() contract.Exporter                           { return b.exports }
func (b *Binding) Close(context.Context) error                           { return nil }

var _ sdk.Binding = (*Binding)(nil)
