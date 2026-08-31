package module

import (
	"net/http"

	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	"github.com/domainry/domainry-foundation/modulehttp"
)

type AuditSurface struct {
	handler *AuditHandler
	mux     *http.ServeMux
}

func NewAuditSurface(application *auditapp.AuditSurfaceApplicationService) (modulehttp.Surface, error) {
	handler, err := NewAuditHandler(application)
	if err != nil {
		return nil, err
	}
	surface := &AuditSurface{handler: handler, mux: http.NewServeMux()}
	surface.mux.HandleFunc("GET /business/audit-events", handler.listBusinessEvents)
	surface.mux.HandleFunc("POST /business/audit-event-exports", handler.prepareBusinessExport)
	surface.mux.HandleFunc("GET /business/audit-event-exports/downloads/{token}", handler.downloadBusinessExport)
	surface.mux.HandleFunc("GET /tenant-admin/audit-events", handler.listGovernanceEvents)
	surface.mux.HandleFunc("GET /tenant-admin/audit-events/export", handler.exportGovernanceEvents)
	surface.mux.HandleFunc("GET /operations/audit-events", handler.listOperationsEvents)
	surface.mux.HandleFunc("GET /operations/audit-events/export", handler.exportOperationsEvents)
	return surface, nil
}

func (*AuditSurface) ContractVersion() string { return modulehttp.ContractVersion }
func (*AuditSurface) Owner() string           { return "audit" }
func (*AuditSurface) Name() string            { return "product" }
func (s *AuditSurface) Handler() http.Handler { return s.mux }

func (*AuditSurface) Routes() []modulehttp.Route {
	public := []modulehttp.Exposure{modulehttp.ExposurePublic}
	governance := []modulehttp.Exposure{modulehttp.ExposurePublic, modulehttp.ExposureTenantAdmin, modulehttp.ExposureOps}
	operations := []modulehttp.Exposure{modulehttp.ExposureTenantAdmin, modulehttp.ExposureOps}
	read := func(pattern, permission, auditClass string, exposures []modulehttp.Exposure) modulehttp.Route {
		return modulehttp.Route{
			Pattern: pattern, Exposures: exposures, Authentication: modulehttp.AuthenticationAuthenticated, Permission: permission,
			Governance: &modulehttp.Governance{EffectClass: modulehttp.EffectRead, HighRiskPolicy: modulehttp.HighRiskNone, IdempotencyDecision: "not_applicable", AuditClass: auditClass},
		}
	}
	return []modulehttp.Route{
		read("GET /business/audit-events", auditapp.AuditPermissionBusinessRead, "business_audit_read", public),
		{Pattern: "POST /business/audit-event-exports", Exposures: public, Authentication: modulehttp.AuthenticationAuthenticated, Permission: auditapp.AuditPermissionBusinessExport, Governance: &modulehttp.Governance{EffectClass: modulehttp.EffectWrite, HighRiskPolicy: modulehttp.HighRiskNone, IdempotencyDecision: "caller_key_required", AuditClass: "business_audit_export_prepare_audit"}},
		read("GET /business/audit-event-exports/downloads/{token}", auditapp.AuditPermissionBusinessExport, "business_audit_export_download_audit", public),
		read("GET /tenant-admin/audit-events", auditapp.AuditPermissionGovernanceRead, "tenant_governance_audit_read", governance),
		read("GET /tenant-admin/audit-events/export", auditapp.AuditPermissionGovernanceExport, "tenant_governance_audit_export", governance),
		read("GET /operations/audit-events", auditapp.AuditPermissionOperationsRead, "operations_audit_read", operations),
		read("GET /operations/audit-events/export", auditapp.AuditPermissionOperationsExport, "operations_audit_export", operations),
	}
}

var _ modulehttp.OpenAPIProvider = (*AuditSurface)(nil)
