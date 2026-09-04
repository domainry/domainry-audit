package auditapp

import (
	"context"
	"errors"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	auditdomain "github.com/domainry/domainry-audit/internal/domain/audit/service"
	"github.com/domainry/domainry-foundation/apperror"
)

const (
	AuditPermissionBusinessRead           = "audit.business.read"
	AuditPermissionBusinessExportPrepare  = "audit.business.export.prepare"
	AuditPermissionBusinessExportDownload = "audit.business.export.download"
	AuditPermissionGovernanceRead         = "audit.governance.read"
	AuditPermissionGovernanceExport       = "audit.governance.export"
	AuditPermissionOperationsRead         = "audit.ops.read"
	AuditPermissionOperationsExport       = "audit.ops.export"
)

// AuditQueryApplicationService owns the product-facing Audit query and
// export use cases. Runtime contributes only the cross-owner record access and
// field-projection capabilities declared by modulehost.AuditApplicationHost.
type AuditQueryApplicationService struct {
	audit   *Service
	exports *ExportService
	host    modulehost.AuditApplicationHost
	clock   Clock
}

type AuditQueryResult = auditdomain.QueryResult

func NewAuditQueryApplicationService(audit *Service, exports *ExportService, host modulehost.AuditApplicationHost, clock Clock) (*AuditQueryApplicationService, error) {
	if audit == nil || exports == nil || host == nil || len(host.AuditExportTokenKey()) < 16 {
		return nil, errors.New("Audit query application host is incomplete")
	}
	if clock == nil {
		clock = systemClock{}
	}
	service := &AuditQueryApplicationService{audit: audit, exports: exports, host: host, clock: clock}
	exports.ConfigureExport(host.AuditExportTokenKey(), service.authorizeExportRecord)
	return service, nil
}

func (s *AuditQueryApplicationService) ResolvePrincipal(ctx context.Context, request modulehost.AuditPrincipalRequest) (modulehost.AuditPrincipal, error) {
	if err := ctx.Err(); err != nil {
		return modulehost.AuditPrincipal{}, err
	}
	if !request.Identity.Known || strings.TrimSpace(request.Identity.WorkspaceID) == "" || strings.TrimSpace(request.Identity.UserID) == "" {
		return modulehost.AuditPrincipal{}, auditQueryError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	principal, err := s.host.ResolveAuditPrincipal(ctx, request)
	if err != nil {
		return modulehost.AuditPrincipal{}, err
	}
	if !principal.Identity.Known || strings.TrimSpace(principal.Identity.WorkspaceID) == "" || strings.TrimSpace(principal.Identity.UserID) == "" {
		return modulehost.AuditPrincipal{}, auditQueryError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	if strings.TrimSpace(principal.AuthorizationRevision) == "" {
		principal.AuthorizationRevision = principal.Identity.AuthorizationRevision
	}
	return principal, nil
}

func (s *AuditQueryApplicationService) BusinessEvents(ctx context.Context, query contract.Query, principal modulehost.AuditPrincipal) (AuditQueryResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionBusinessRead, s.clock.Now())
	if err != nil {
		return AuditQueryResult{}, err
	}
	if query.ObjectKey != "" && query.RecordID != "" {
		if err := s.host.AuthorizeAuditRecord(ctx, principal, query.ObjectKey, query.RecordID); err != nil {
			return AuditQueryResult{}, err
		}
	}
	return s.query(ctx, auditdomain.EventClassBusiness, query, principal, scope)
}

func (s *AuditQueryApplicationService) GovernanceEvents(ctx context.Context, query contract.Query, principal modulehost.AuditPrincipal) (AuditQueryResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionGovernanceRead, s.clock.Now())
	if err != nil {
		return AuditQueryResult{}, err
	}
	return s.query(ctx, auditdomain.EventClassGovernance, query, principal, scope)
}

func (s *AuditQueryApplicationService) ExportGovernanceEvents(ctx context.Context, query contract.Query, principal modulehost.AuditPrincipal) (AuditQueryResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionGovernanceExport, s.clock.Now())
	if err != nil {
		return AuditQueryResult{}, err
	}
	return s.query(ctx, auditdomain.EventClassGovernance, query, principal, scope)
}

func (s *AuditQueryApplicationService) OperationsEvents(ctx context.Context, query contract.Query, principal modulehost.AuditPrincipal) (AuditQueryResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionOperationsRead, s.clock.Now())
	if err != nil {
		return AuditQueryResult{}, err
	}
	return s.query(ctx, auditdomain.EventClassOperations, query, principal, scope)
}

func (s *AuditQueryApplicationService) ExportOperationsEvents(ctx context.Context, query contract.Query, principal modulehost.AuditPrincipal) (AuditQueryResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionOperationsExport, s.clock.Now())
	if err != nil {
		return AuditQueryResult{}, err
	}
	return s.query(ctx, auditdomain.EventClassOperations, query, principal, scope)
}

func (s *AuditQueryApplicationService) PrepareBusinessExport(ctx context.Context, request contract.ExportRequest, idempotencyKey string, principal modulehost.AuditPrincipal) (contract.ExportPrepared, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionBusinessExportPrepare, s.clock.Now())
	if err != nil {
		return contract.ExportPrepared{}, err
	}
	prepared, err := s.exports.PrepareExportWithinDataScope(ctx, request, strings.TrimSpace(idempotencyKey), auditExportPrincipal(principal), scope, s.authorizeExportRecord)
	if err != nil {
		return contract.ExportPrepared{}, err
	}
	prepared.ReportSource = "business_audit_events"
	return prepared, nil
}

func (s *AuditQueryApplicationService) DownloadBusinessExport(ctx context.Context, token string, principal modulehost.AuditPrincipal) ([]byte, string, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionBusinessExportDownload, s.clock.Now())
	if err != nil {
		return nil, "", err
	}
	return s.exports.DownloadExportWithinDataScope(ctx, strings.TrimSpace(token), auditExportPrincipal(principal), scope, s.authorizeExportRecord)
}

func (s *AuditQueryApplicationService) query(ctx context.Context, kind auditdomain.EventClass, query contract.Query, principal modulehost.AuditPrincipal, scope auditrepository.DataScope) (AuditQueryResult, error) {
	plan, err := auditdomain.PlanQuery(kind, query, principal.Identity.UserID, s.clock.Now())
	if err != nil {
		return AuditQueryResult{}, auditQueryError(apperror.KindBadRequest, "backend.audit.cursor_invalid", err)
	}
	events, err := s.audit.ListWithinDataScope(ctx, principal.Identity.WorkspaceID, plan.Query, scope)
	if err != nil {
		return AuditQueryResult{}, auditQueryError(apperror.KindInternal, "backend.internal", err)
	}
	events, err = s.host.ProjectAuditEvents(ctx, principal, events)
	if err != nil {
		return AuditQueryResult{}, err
	}
	return auditdomain.ProjectQuery(events, plan), nil
}

func (s *AuditQueryApplicationService) authorizeExportRecord(ctx context.Context, filter contract.ExportFilter, exportPrincipal contract.ExportPrincipal) error {
	context, ok := exportPrincipal.AuthorizationContext.(auditExportAuthorizationContext)
	if !ok {
		return auditQueryError(apperror.KindForbidden, "backend.audit.export_scope_changed", nil)
	}
	if filter.ObjectKey == "" || filter.RecordID == "" {
		return nil
	}
	return s.host.AuthorizeAuditRecord(ctx, context.Principal, filter.ObjectKey, filter.RecordID)
}

type auditExportAuthorizationContext struct {
	Principal modulehost.AuditPrincipal
}

func auditExportPrincipal(principal modulehost.AuditPrincipal) contract.ExportPrincipal {
	return contract.ExportPrincipal{
		WorkspaceID: principal.Identity.WorkspaceID, UserID: principal.Identity.UserID,
		RoleKey: principal.Identity.RoleKey, AuthorizationRevision: principal.AuthorizationRevision,
		AuthorizationContext: auditExportAuthorizationContext{Principal: principal},
	}
}

func auditQueryError(kind apperror.ErrorKind, code string, err error) error {
	return apperror.New(kind, code, err, nil)
}
