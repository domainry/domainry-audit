package auditapp

import (
	"context"
	"encoding/json"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	auditservice "github.com/domainry/domainry-audit/internal/domain/audit/service"
)

type Store interface {
	contract.PreparedAppender
	contract.Reader
	contract.SubjectLifecycle
	ListWithinDataScope(context.Context, string, contract.Query, auditrepository.DataScope) ([]contract.Event, error)
}

type Service struct {
	store   Store
	factory *auditservice.EventFactory
}

func NewService(store Store, clock auditservice.Clock) *Service {
	return &Service{store: store, factory: auditservice.NewEventFactory(clock)}
}

func (s *Service) Build(_ context.Context, request contract.AppendRequest) (contract.Event, error) {
	return s.factory.Build(request)
}
func (s *Service) Append(ctx context.Context, request contract.AppendRequest) (contract.Event, error) {
	event, err := s.Build(ctx, request)
	if err != nil {
		return event, err
	}
	return event, s.store.AppendPrepared(ctx, event)
}
func (s *Service) AppendTelemetry(ctx context.Context, request contract.AppendRequest) {
	_, _ = s.Append(ctx, request)
}
func (s *Service) AppendWithin(ctx context.Context, tx contract.Transaction, request contract.AppendRequest) (contract.Event, error) {
	event, err := s.Build(ctx, request)
	if err != nil {
		return event, err
	}
	return event, s.store.AppendPreparedWithin(ctx, tx, event)
}
func (s *Service) AppendPrepared(ctx context.Context, event contract.Event) error {
	return s.store.AppendPrepared(ctx, event)
}
func (s *Service) AppendPreparedWithin(ctx context.Context, tx contract.Transaction, event contract.Event) error {
	return s.store.AppendPreparedWithin(ctx, tx, event)
}
func (s *Service) List(ctx context.Context, workspaceID string, query contract.Query) ([]contract.Event, error) {
	return s.store.List(ctx, workspaceID, query)
}
func (s *Service) ListWithinDataScope(ctx context.Context, workspaceID string, query contract.Query, scope auditrepository.DataScope) ([]contract.Event, error) {
	return s.store.ListWithinDataScope(ctx, workspaceID, query, scope)
}
func (s *Service) ListSystem(ctx context.Context, query contract.Query) ([]contract.Event, error) {
	return s.store.ListSystem(ctx, query)
}
func (s *Service) Options(ctx context.Context, workspaceID string, query contract.OptionQuery) ([]contract.Option, error) {
	return s.store.Options(ctx, workspaceID, query)
}
func (s *Service) PreviewSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	return s.store.PreviewSubject(ctx, workspaceID, identity)
}
func (s *Service) ExportSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	return s.store.ExportSubject(ctx, workspaceID, identity)
}
func (s *Service) EraseSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	return s.store.EraseSubject(ctx, workspaceID, identity)
}
