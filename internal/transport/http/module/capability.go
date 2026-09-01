package module

import (
	"encoding/json"
	"strings"

	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/modulehttp"
)

func NewCapabilityBinding() (*modulecapability.StaticBinding, error) {
	surface := &AuditSurface{}
	allRoutes := surface.Routes()
	operations := surface.OpenAPIOperations()
	groups := map[string][]modulehttp.Route{}
	for _, route := range allRoutes {
		groups[auditCapabilityCategory(route.Pattern)] = append(groups[auditCapabilityCategory(route.Pattern)], route)
	}
	keys := []string{"audit.business", "audit.governance", "audit.operations"}
	documents := make([]modulecapability.CategoryDocument, 0, len(keys))
	for _, key := range keys {
		name, description, assembly := auditCategoryMetadata(key)
		document, err := modulecapability.CategoryFromHTTPRoutes(modulecapability.HTTPRouteCategory{
			Owner: "audit", Category: modulecapability.CategorySummary{Key: key, Name: name, Description: description, AssemblyChains: assembly, ValidationScopes: []string{}},
			Routes: groups[key], Operations: operations,
			Components: map[string]map[string]json.RawMessage{
				"schemas":         {"Error": json.RawMessage(`{"type":"object","required":["code"],"properties":{"code":{"type":"string"},"message":{"type":"string"}}}`)},
				"securitySchemes": {"BearerAuth": json.RawMessage(`{"type":"http","scheme":"bearer","bearerFormat":"JWT"}`)},
			},
		})
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	summary := modulecapability.ModuleSummary{
		Identity: modulecapability.ModuleIdentity{Key: "audit", SourceOwner: "audit", ModuleVersion: "domainry-audit-protocol-v1", ValidationRevision: "audit-owner-validation-v1", SupportedDeploymentModes: []modulecapability.DeploymentMode{modulecapability.DeploymentModeModule}},
		Name:     "Audit", Description: "Immutable business, governance, technical, and security event history with scoped query and export.",
		Scenarios: modulecapability.AdaptationScenarios{
			UseWhen:              []string{"A PRD requires immutable evidence of business or administrative changes, actor history, compliance review, or scoped audit export"},
			DoNotUseWhen:         []string{"The requirement is application logging, metrics, or transient debugging telemetry without an immutable audit-evidence obligation"},
			RequirementSignals:   []string{"audit trail", "who changed what and when", "compliance evidence", "immutable event export", "subject lifecycle evidence"},
			ProvidedCapabilities: []string{"audit.append", "audit.query", "audit.export", "audit.subject_lifecycle"}, RequiredModules: []string{"identity"}, OptionalModules: []string{"lifecycle"}, ConflictingModules: []string{},
			AssemblyChains: []string{"business_mutation_to_transactional_audit_append", "audit_retention_with_lifecycle_policy", "identity_scope_before_audit_query_or_export"}, ValidationScopes: []string{},
			SelectionExamples: []modulecapability.ScenarioExample{{Requirement: "Compliance users must export who changed a customer record during a date range", Reason: "Audit owns immutable actor-attributed event history and scoped export"}},
			RejectionExamples: []modulecapability.ScenarioExample{{Requirement: "Show service latency and error-rate charts", Reason: "Monitoring owns operational telemetry; no immutable audit history is requested"}},
		},
	}
	return modulecapability.NewStaticBinding(summary, documents, nil)
}

func auditCapabilityCategory(pattern string) string {
	_, path, _ := strings.Cut(pattern, " ")
	if strings.HasPrefix(path, "/business/") {
		return "audit.business"
	}
	if strings.HasPrefix(path, "/tenant-admin/") {
		return "audit.governance"
	}
	return "audit.operations"
}

func auditCategoryMetadata(key string) (string, string, []string) {
	switch key {
	case "audit.business":
		return "Business audit", "Query and export workspace-scoped business audit evidence under the current actor and data scope.", []string{"business_mutation_to_transactional_audit_append", "identity_scope_before_audit_query_or_export"}
	case "audit.governance":
		return "Governance audit", "Query and export tenant governance audit evidence for authorized administrators.", []string{"identity_scope_before_audit_query_or_export"}
	default:
		return "Operations audit", "Query and export retained technical and security audit evidence for operators.", []string{"audit_retention_with_lifecycle_policy"}
	}
}
