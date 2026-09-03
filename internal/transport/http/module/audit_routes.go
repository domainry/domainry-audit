package module

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	actioncontract "github.com/domainry/domainry-foundation/action"
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
	handlers := map[string]http.HandlerFunc{
		auditapp.AuditPermissionBusinessRead:           handler.listBusinessEvents,
		auditapp.AuditPermissionBusinessExportPrepare:  handler.prepareBusinessExport,
		auditapp.AuditPermissionBusinessExportDownload: handler.downloadBusinessExport,
		auditapp.AuditPermissionGovernanceRead:         handler.listGovernanceEvents,
		auditapp.AuditPermissionGovernanceExport:       handler.exportGovernanceEvents,
		auditapp.AuditPermissionOperationsRead:         handler.listOperationsEvents,
		auditapp.AuditPermissionOperationsExport:       handler.exportOperationsEvents,
	}
	operations := auditOpenAPIOperationsByAction()
	for _, route := range surface.Routes() {
		key := strings.TrimSpace(route.Action.Key)
		implementation, found := handlers[key]
		if !found {
			return nil, fmt.Errorf("Audit Action %q has no HTTP handler", key)
		}
		if _, found := operations[key]; !found {
			return nil, fmt.Errorf("Audit Action %q has no OpenAPI operation", key)
		}
		surface.mux.HandleFunc(route.Pattern(), implementation)
		delete(handlers, key)
		delete(operations, key)
	}
	if len(handlers) != 0 || len(operations) != 0 {
		keys := make([]string, 0, len(handlers)+len(operations))
		for key := range handlers {
			keys = append(keys, "handler:"+key)
		}
		for key := range operations {
			keys = append(keys, "openapi:"+key)
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("Audit implementations have no Action manifest entries: %v", keys)
	}
	return surface, nil
}

func (*AuditSurface) ContractVersion() string { return modulehttp.ContractVersion }
func (*AuditSurface) Owner() string           { return "audit" }
func (*AuditSurface) Name() string            { return "product" }
func (s *AuditSurface) Handler() http.Handler { return s.mux }

func (*AuditSurface) Routes() []modulehttp.Route {
	public := []actioncontract.Exposure{actioncontract.ExposurePublic}
	governance := []actioncontract.Exposure{actioncontract.ExposurePublic, actioncontract.ExposureTenantAdmin, actioncontract.ExposureOps}
	operations := []actioncontract.Exposure{actioncontract.ExposureTenantAdmin, actioncontract.ExposureOps}
	route := func(pattern, permission, label, auditClass, pageRoute string, exposures []actioncontract.Exposure, effect actioncontract.EffectClass, risk actioncontract.RiskLevel, idempotency string) modulehttp.Route {
		method, path, _ := strings.Cut(pattern, " ")
		separator := strings.LastIndex(permission, ".")
		action := actioncontract.ActionDefinition{
			Key: permission, Owner: "module:audit", SourceKind: "module_surface", CapabilityKey: "audit.product", CapabilityLabel: "Audit",
			OperationKey: permission[separator+1:], OperationLabel: label, Label: label, Exposures: exposures,
			Authorization: actioncontract.Authorization{Strategy: actioncontract.AuthorizationAuthenticated},
			HTTP:          &actioncontract.HTTPBinding{Method: method, RouteTemplate: path}, Permission: &actioncontract.PermissionDefinition{
				Key: permission, Owner: "module:audit", ResourceKey: permission[:separator], OperationKey: permission[separator+1:], Label: label, Category: "Audit", LifecycleStatus: actioncontract.LifecycleActive,
			},
			EffectClass: effect, RiskLevel: risk, IdempotencyDecision: idempotency, AuditClass: auditClass, LifecycleStatus: actioncontract.LifecycleActive,
		}
		if pageRoute != "" {
			action.Pages = []actioncontract.PageBinding{{Route: pageRoute, Label: "治理审计"}}
		}
		return modulehttp.Route{Action: action}
	}
	return []modulehttp.Route{
		route("GET /business/audit-events", auditapp.AuditPermissionBusinessRead, "Read business audit events", "business_audit_read", "", public, actioncontract.EffectRead, actioncontract.RiskLow, "not_applicable"),
		route("POST /business/audit-event-exports", auditapp.AuditPermissionBusinessExportPrepare, "Prepare business audit export", "business_audit_export_prepare_audit", "", public, actioncontract.EffectWrite, actioncontract.RiskHigh, "caller_key_required"),
		route("GET /business/audit-event-exports/downloads/{token}", auditapp.AuditPermissionBusinessExportDownload, "Download business audit export", "business_audit_export_download_audit", "", public, actioncontract.EffectRead, actioncontract.RiskHigh, "not_applicable"),
		route("GET /tenant-admin/audit-events", auditapp.AuditPermissionGovernanceRead, "Read governance audit events", "tenant_governance_audit_read", "/admin/system/audit", governance, actioncontract.EffectRead, actioncontract.RiskMedium, "not_applicable"),
		route("GET /tenant-admin/audit-events/export", auditapp.AuditPermissionGovernanceExport, "Export governance audit events", "tenant_governance_audit_export", "", governance, actioncontract.EffectRead, actioncontract.RiskHigh, "not_applicable"),
		route("GET /operations/audit-events", auditapp.AuditPermissionOperationsRead, "Read operations audit events", "operations_audit_read", "", operations, actioncontract.EffectRead, actioncontract.RiskMedium, "not_applicable"),
		route("GET /operations/audit-events/export", auditapp.AuditPermissionOperationsExport, "Export operations audit events", "operations_audit_export", "", operations, actioncontract.EffectRead, actioncontract.RiskHigh, "not_applicable"),
	}
}

// AuthorizationActions returns detached source-owned Action declarations for
// build-time consumers such as a host frontend contract generator. Runtime
// mounting continues to consume the same Routes method, so this is a
// projection rather than a second manifest.
func AuthorizationActions() []actioncontract.ActionDefinition {
	routes := (&AuditSurface{}).Routes()
	actions := make([]actioncontract.ActionDefinition, len(routes))
	for index, route := range routes {
		actions[index] = actioncontract.CloneDefinition(route.Action)
	}
	return actions
}

var _ modulehttp.OpenAPIProvider = (*AuditSurface)(nil)
