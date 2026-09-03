package auditapp

import (
	"reflect"
	"strings"
	"time"

	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	"github.com/domainry/domainry-foundation/apperror"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

// resolveAuditDataScope requires one exact functional grant and the data
// policy for that same exact Permission key. It translates only the closed
// role-authoring vocabulary; unsupported deny predicates fail closed.
func resolveAuditDataScope(principal identitysdk.Principal, permission string, now time.Time) (auditrepository.DataScope, error) {
	denied := func() (auditrepository.DataScope, error) {
		return auditrepository.DataScope{}, auditSurfaceError(apperror.KindForbidden, "backend.audit.view_permission_required", nil)
	}
	permission = strings.TrimSpace(permission)
	separator := strings.LastIndexByte(permission, '.')
	if !principal.Known || separator <= 0 || separator == len(permission)-1 || !principal.HasPermission(permission) || principal.AccessBundle == nil {
		return denied()
	}
	bundle := principal.AccessBundle
	if err := bundle.Validate(now.UTC()); err != nil ||
		strings.TrimSpace(string(bundle.Subject.WorkspaceID)) != strings.TrimSpace(principal.WorkspaceID) ||
		strings.TrimSpace(string(bundle.Subject.SubjectID)) != strings.TrimSpace(principal.UserID) {
		return denied()
	}
	resource, action := permission[:separator], permission[separator+1:]
	scope := auditrepository.DataScope{}
	found := false
	for _, policy := range bundle.DataPolicies {
		if strings.TrimSpace(string(policy.Resource)) != resource || strings.TrimSpace(string(policy.Action)) != action {
			continue
		}
		if policy.Effect != identitysdk.EffectAllow {
			// Audit does not have enough resource facts to translate arbitrary
			// deny predicates without risking an authorization expansion.
			return denied()
		}
		if !reflect.DeepEqual(policy.Predicate, canonicalAuditScopePredicate(policy.DataScopes)) {
			return denied()
		}
		found = true
		for _, value := range policy.DataScopes {
			switch value {
			case identitysdk.DataScopeAll:
				scope.All = true
			case identitysdk.DataScopeOwner:
				scope.SubjectIDs = append(scope.SubjectIDs, string(bundle.Subject.SubjectID))
			case identitysdk.DataScopeOrg:
				scope.OrganizationIDs = append(scope.OrganizationIDs, bundle.Subject.OrgID)
			case identitysdk.DataScopeOrgChild:
				scope.OrganizationIDs = append(scope.OrganizationIDs, bundle.Subject.OrgScopeIDs...)
			case identitysdk.DataScopeTargetOrg:
				scope.OrganizationIDs = append(scope.OrganizationIDs, bundle.Subject.SupportOrgScopeIDs...)
			default:
				return denied()
			}
		}
	}
	if !found {
		return denied()
	}
	for _, guardrail := range bundle.Guardrails {
		resourceMatches := guardrail.Resource == "" || strings.TrimSpace(string(guardrail.Resource)) == resource
		actionMatches := guardrail.Action == "" || strings.TrimSpace(string(guardrail.Action)) == action
		if resourceMatches && actionMatches && guardrail.Predicate != nil && strings.TrimSpace(guardrail.Field) == "" {
			return denied()
		}
	}
	return scope.Normalized(), nil
}

func canonicalAuditScopePredicate(scopes []identitysdk.DataScope) identitysdk.Predicate {
	parts := make([]identitysdk.Predicate, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case identitysdk.DataScopeAll:
			return identitysdk.Predicate{}
		case identitysdk.DataScopeOwner:
			parts = append(parts, identitysdk.Predicate{Fact: "owner_user_id", Operator: identitysdk.OperatorEqual, Value: "$subject.id"})
		case identitysdk.DataScopeOrg:
			parts = append(parts, identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorEqual, Value: "$subject.org_id"})
		case identitysdk.DataScopeOrgChild:
			parts = append(parts, identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.org_scope_ids"})
		case identitysdk.DataScopeTargetOrg:
			parts = append(parts, identitysdk.Predicate{Fact: "owner_org_id", Operator: identitysdk.OperatorIn, Value: "$subject.support_org_scope_ids"})
		default:
			return identitysdk.Predicate{Fact: "__audit_scope_unsupported__", Operator: identitysdk.OperatorEqual, Value: true}
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return identitysdk.Predicate{Any: parts}
}
