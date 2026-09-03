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

// AuditSurfaceApplicationService owns the product-facing Audit query and
// export use cases. Runtime contributes only the cross-owner record access and
// field-projection capabilities declared by modulehost.AuditApplicationHost.
type AuditSurfaceApplicationService struct {
	audit   *Service
	exports *ExportService
	host    modulehost.AuditApplicationHost
	clock   Clock
}

type AuditSurfaceResult = auditdomain.SurfaceResult

func NewAuditSurfaceApplicationService(audit *Service, exports *ExportService, host modulehost.AuditApplicationHost, clock Clock) (*AuditSurfaceApplicationService, error) {
	if audit == nil || exports == nil || host == nil || len(host.AuditExportTokenKey()) < 16 {
		return nil, errors.New("Audit surface application host is incomplete")
	}
	if clock == nil {
		clock = systemClock{}
	}
	service := &AuditSurfaceApplicationService{audit: audit, exports: exports, host: host, clock: clock}
	exports.ConfigureExport(host.AuditExportTokenKey(), service.authorizeExportRecord)
	return service, nil
}

func (s *AuditSurfaceApplicationService) ResolvePrincipal(ctx context.Context, request modulehost.AuditSurfacePrincipalRequest) (modulehost.AuditSurfacePrincipal, error) {
	if err := ctx.Err(); err != nil {
		return modulehost.AuditSurfacePrincipal{}, err
	}
	if !request.Identity.Known || strings.TrimSpace(request.Identity.WorkspaceID) == "" || strings.TrimSpace(request.Identity.UserID) == "" {
		return modulehost.AuditSurfacePrincipal{}, auditSurfaceError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	principal, err := s.host.ResolveAuditSurfacePrincipal(ctx, request)
	if err != nil {
		return modulehost.AuditSurfacePrincipal{}, err
	}
	if !principal.Identity.Known || strings.TrimSpace(principal.Identity.WorkspaceID) == "" || strings.TrimSpace(principal.Identity.UserID) == "" {
		return modulehost.AuditSurfacePrincipal{}, auditSurfaceError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	if strings.TrimSpace(principal.AuthorizationRevision) == "" {
		principal.AuthorizationRevision = principal.Identity.AuthorizationRevision
	}
	return principal, nil
}

func (s *AuditSurfaceApplicationService) BusinessEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionBusinessRead, s.clock.Now())
	if err != nil {
		return AuditSurfaceResult{}, err
	}
	if query.ObjectKey != "" && query.RecordID != "" {
		if err := s.host.AuthorizeAuditRecord(ctx, principal, query.ObjectKey, query.RecordID); err != nil {
			return AuditSurfaceResult{}, err
		}
	}
	return s.surface(ctx, auditdomain.SurfaceBusiness, query, principal, scope)
}

func (s *AuditSurfaceApplicationService) GovernanceEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionGovernanceRead, s.clock.Now())
	if err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceGovernance, query, principal, scope)
}

func (s *AuditSurfaceApplicationService) ExportGovernanceEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionGovernanceExport, s.clock.Now())
	if err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceGovernance, query, principal, scope)
}

func (s *AuditSurfaceApplicationService) OperationsEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionOperationsRead, s.clock.Now())
	if err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceOperations, query, principal, scope)
}

func (s *AuditSurfaceApplicationService) ExportOperationsEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionOperationsExport, s.clock.Now())
	if err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceOperations, query, principal, scope)
}

func (s *AuditSurfaceApplicationService) PrepareBusinessExport(ctx context.Context, request contract.ExportRequest, idempotencyKey string, principal modulehost.AuditSurfacePrincipal) (contract.ExportPrepared, error) {
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

func (s *AuditSurfaceApplicationService) DownloadBusinessExport(ctx context.Context, token string, principal modulehost.AuditSurfacePrincipal) ([]byte, string, error) {
	scope, err := resolveAuditDataScope(principal.Identity, AuditPermissionBusinessExportDownload, s.clock.Now())
	if err != nil {
		return nil, "", err
	}
	return s.exports.DownloadExportWithinDataScope(ctx, strings.TrimSpace(token), auditExportPrincipal(principal), scope, s.authorizeExportRecord)
}

func (s *AuditSurfaceApplicationService) surface(ctx context.Context, kind auditdomain.SurfaceKind, query contract.Query, principal modulehost.AuditSurfacePrincipal, scope auditrepository.DataScope) (AuditSurfaceResult, error) {
	plan, err := auditdomain.PlanSurface(kind, query, principal.Identity.UserID, s.clock.Now())
	if err != nil {
		return AuditSurfaceResult{}, auditSurfaceError(apperror.KindBadRequest, "backend.audit.cursor_invalid", err)
	}
	events, err := s.audit.ListWithinDataScope(ctx, principal.Identity.WorkspaceID, plan.Query, scope)
	if err != nil {
		return AuditSurfaceResult{}, auditSurfaceError(apperror.KindInternal, "backend.internal", err)
	}
	events, err = s.host.ProjectAuditEvents(ctx, principal, events)
	if err != nil {
		return AuditSurfaceResult{}, err
	}
	return auditdomain.ProjectSurface(events, plan), nil
}

func (s *AuditSurfaceApplicationService) authorizeExportRecord(ctx context.Context, filter contract.ExportFilter, exportPrincipal contract.ExportPrincipal) error {
	context, ok := exportPrincipal.AuthorizationContext.(auditExportAuthorizationContext)
	if !ok {
		return auditSurfaceError(apperror.KindForbidden, "backend.audit.export_scope_changed", nil)
	}
	if filter.ObjectKey == "" || filter.RecordID == "" {
		return nil
	}
	return s.host.AuthorizeAuditRecord(ctx, context.Principal, filter.ObjectKey, filter.RecordID)
}

type auditExportAuthorizationContext struct {
	Principal modulehost.AuditSurfacePrincipal
}

func auditExportPrincipal(principal modulehost.AuditSurfacePrincipal) contract.ExportPrincipal {
	return contract.ExportPrincipal{
		WorkspaceID: principal.Identity.WorkspaceID, UserID: principal.Identity.UserID,
		RoleKey: principal.Identity.RoleKey, AuthorizationRevision: principal.AuthorizationRevision,
		AuthorizationContext: auditExportAuthorizationContext{Principal: principal},
	}
}

func auditSurfaceError(kind apperror.ErrorKind, code string, err error) error {
	return apperror.New(kind, code, err, nil)
}
