package auditapp

import (
	"context"
	"errors"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditdomain "github.com/domainry/domainry-audit/internal/domain/audit/service"
	"github.com/domainry/domainry-foundation/apperror"
)

const (
	AuditPermissionBusinessRead     = "audit.business.read"
	AuditPermissionBusinessExport   = "audit.business.export"
	AuditPermissionGovernanceRead   = "audit.governance.read"
	AuditPermissionGovernanceExport = "audit.governance.export"
	AuditPermissionOperationsRead   = "audit.ops.read"
	AuditPermissionOperationsExport = "audit.ops.export"
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
	exports.ConfigureExport(host.AuditExportTokenKey(), service.authorizeExport)
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
	if err := requireAuditPermission(principal, AuditPermissionBusinessRead); err != nil {
		return AuditSurfaceResult{}, err
	}
	if query.ObjectKey != "" && query.RecordID != "" {
		if err := s.host.AuthorizeAuditRecord(ctx, principal, query.ObjectKey, query.RecordID); err != nil {
			return AuditSurfaceResult{}, err
		}
	}
	return s.surface(ctx, auditdomain.SurfaceBusiness, query, principal)
}

func (s *AuditSurfaceApplicationService) GovernanceEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	if err := requireAuditPermission(principal, AuditPermissionGovernanceRead); err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceGovernance, query, principal)
}

func (s *AuditSurfaceApplicationService) ExportGovernanceEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	if err := requireAuditPermissions(principal, AuditPermissionGovernanceRead, AuditPermissionGovernanceExport); err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceGovernance, query, principal)
}

func (s *AuditSurfaceApplicationService) OperationsEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	if err := requireAuditPermission(principal, AuditPermissionOperationsRead); err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceOperations, query, principal)
}

func (s *AuditSurfaceApplicationService) ExportOperationsEvents(ctx context.Context, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	if err := requireAuditPermissions(principal, AuditPermissionOperationsRead, AuditPermissionOperationsExport); err != nil {
		return AuditSurfaceResult{}, err
	}
	return s.surface(ctx, auditdomain.SurfaceOperations, query, principal)
}

func (s *AuditSurfaceApplicationService) PrepareBusinessExport(ctx context.Context, request contract.ExportRequest, idempotencyKey string, principal modulehost.AuditSurfacePrincipal) (contract.ExportPrepared, error) {
	if err := requireAuditPermissions(principal, AuditPermissionBusinessRead, AuditPermissionBusinessExport); err != nil {
		return contract.ExportPrepared{}, err
	}
	prepared, err := s.exports.PrepareExport(ctx, request, strings.TrimSpace(idempotencyKey), auditExportPrincipal(principal))
	if err != nil {
		return contract.ExportPrepared{}, err
	}
	prepared.ReportSource = "business_audit_events"
	return prepared, nil
}

func (s *AuditSurfaceApplicationService) DownloadBusinessExport(ctx context.Context, token string, principal modulehost.AuditSurfacePrincipal) ([]byte, string, error) {
	if err := requireAuditPermissions(principal, AuditPermissionBusinessRead, AuditPermissionBusinessExport); err != nil {
		return nil, "", err
	}
	return s.exports.DownloadExport(ctx, strings.TrimSpace(token), auditExportPrincipal(principal))
}

func (s *AuditSurfaceApplicationService) surface(ctx context.Context, kind auditdomain.SurfaceKind, query contract.Query, principal modulehost.AuditSurfacePrincipal) (AuditSurfaceResult, error) {
	plan, err := auditdomain.PlanSurface(kind, query, principal.Identity.UserID, s.clock.Now())
	if err != nil {
		return AuditSurfaceResult{}, auditSurfaceError(apperror.KindBadRequest, "backend.audit.cursor_invalid", err)
	}
	events, err := s.audit.List(ctx, principal.Identity.WorkspaceID, plan.Query)
	if err != nil {
		return AuditSurfaceResult{}, auditSurfaceError(apperror.KindInternal, "backend.internal", err)
	}
	events, err = s.host.ProjectAuditEvents(ctx, principal, events)
	if err != nil {
		return AuditSurfaceResult{}, err
	}
	return auditdomain.ProjectSurface(events, plan), nil
}

func (s *AuditSurfaceApplicationService) authorizeExport(ctx context.Context, filter contract.ExportFilter, exportPrincipal contract.ExportPrincipal) error {
	principal, ok := exportPrincipal.AuthorizationContext.(modulehost.AuditSurfacePrincipal)
	if !ok {
		return auditSurfaceError(apperror.KindForbidden, "backend.audit.export_scope_changed", nil)
	}
	if err := requireAuditPermissions(principal, AuditPermissionBusinessRead, AuditPermissionBusinessExport); err != nil {
		return err
	}
	if filter.ObjectKey == "" || filter.RecordID == "" {
		return nil
	}
	return s.host.AuthorizeAuditRecord(ctx, principal, filter.ObjectKey, filter.RecordID)
}

func auditExportPrincipal(principal modulehost.AuditSurfacePrincipal) contract.ExportPrincipal {
	return contract.ExportPrincipal{
		WorkspaceID: principal.Identity.WorkspaceID, UserID: principal.Identity.UserID,
		RoleKey: principal.Identity.RoleKey, AuthorizationRevision: principal.AuthorizationRevision,
		AuthorizationContext: principal,
	}
}

func requireAuditPermissions(principal modulehost.AuditSurfacePrincipal, permissions ...string) error {
	if len(permissions) == 0 || !principal.Identity.Known || !principal.Identity.HasAllPermissions(permissions) {
		return auditSurfaceError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	return nil
}

func requireAuditPermission(principal modulehost.AuditSurfacePrincipal, permission string) error {
	if !principal.Identity.Known || !principal.Identity.HasPermission(permission) {
		return auditSurfaceError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	return nil
}

func auditSurfaceError(kind apperror.ErrorKind, code string, err error) error {
	return apperror.New(kind, code, err, nil)
}
