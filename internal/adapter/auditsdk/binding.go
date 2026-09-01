// Package auditsdk adapts Audit application services to the public SDK.
package auditsdk

import (
	"context"
	"errors"
	"fmt"
	"sync"

	sdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	exportstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/export"
	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/modulehttp"
)

type Binding struct {
	audit       *auditapp.Service
	exports     *auditapp.ExportService
	exportStore *exportstore.Store
	mu          sync.RWMutex
	bindHost    func(modulehost.AuditApplicationHost) ([]modulehttp.Surface, error)
	surfaces    []modulehttp.Surface
	actions     []actioncontract.ActionDefinition
	capability  modulecapability.Binding
}

func NewBinding(audit *auditapp.Service, exports *auditapp.ExportService, exportStore *exportstore.Store, capability modulecapability.Binding, actions []actioncontract.ActionDefinition) (*Binding, error) {
	if capability == nil {
		return nil, fmt.Errorf("Audit capability binding is required")
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("Audit authorization Actions are required")
	}
	detached := make([]actioncontract.ActionDefinition, len(actions))
	for index := range actions {
		detached[index] = actioncontract.CloneDefinition(actions[index])
	}
	return &Binding{audit: audit, exports: exports, exportStore: exportStore, capability: capability, actions: detached}, nil
}

func (b *Binding) CapabilitySummary(ctx context.Context) (modulecapability.ModuleSummary, error) {
	return b.capability.CapabilitySummary(ctx)
}
func (b *Binding) CapabilityCategory(ctx context.Context, key string) (modulecapability.CategoryDocument, error) {
	return b.capability.CapabilityCategory(ctx, key)
}
func (b *Binding) ValidateCapabilityCandidate(ctx context.Context, request modulecapability.ValidationRequest) (modulecapability.ValidationResult, error) {
	return b.capability.ValidateCapabilityCandidate(ctx, request)
}

func (b *Binding) Descriptor() sdk.Descriptor {
	return sdk.Descriptor{ProtocolVersion: sdk.ProtocolVersionV1, Mode: sdk.DeploymentModeModule, Capabilities: sdk.Capabilities{TransactionalAppend: true, Query: true, Export: true, SubjectLifecycle: true, HTTPSurface: true}}
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

func (b *Binding) SetApplicationHostBinder(bind func(modulehost.AuditApplicationHost) ([]modulehttp.Surface, error)) {
	b.mu.Lock()
	b.bindHost = bind
	b.mu.Unlock()
}

func (b *Binding) BindApplicationHost(host modulehost.AuditApplicationHost) error {
	b.mu.RLock()
	bind := b.bindHost
	b.mu.RUnlock()
	if bind == nil {
		return errors.New("Audit application host binder is unavailable")
	}
	surfaces, err := bind(host)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.surfaces = append([]modulehttp.Surface(nil), surfaces...)
	b.mu.Unlock()
	return nil
}

func (b *Binding) HTTPSurfaces() []modulehttp.Surface {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]modulehttp.Surface(nil), b.surfaces...)
}

func (b *Binding) AuthorizationActions() ([]actioncontract.ActionDefinition, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]actioncontract.ActionDefinition, len(b.actions))
	for index := range b.actions {
		result[index] = actioncontract.CloneDefinition(b.actions[index])
	}
	return result, nil
}

var _ sdk.Binding = (*Binding)(nil)
var _ sdk.ApplicationHostBinder = (*Binding)(nil)
var _ modulehttp.Provider = (*Binding)(nil)
var _ actioncontract.Provider = (*Binding)(nil)
