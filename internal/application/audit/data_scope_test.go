package auditapp

import (
	"reflect"
	"strings"
	"testing"
	"time"

	identitysdk "github.com/domainry/domainry-identity-sdk"
)

func TestResolveAuditDataScopeKeepsExactPermissionScopesIndependent(t *testing.T) {
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	principal := auditScopeTestPrincipal(now, map[string][]identitysdk.DataScope{
		AuditPermissionBusinessRead:     {identitysdk.DataScopeOwner},
		AuditPermissionGovernanceRead:   {identitysdk.DataScopeOrgChild},
		AuditPermissionOperationsExport: {identitysdk.DataScopeAll},
	})
	principal.AccessBundle.Subject.OrgScopeIDs = []string{"org-a", "org-b"}

	owner, err := resolveAuditDataScope(principal, AuditPermissionBusinessRead, now)
	if err != nil || owner.All || !reflect.DeepEqual(owner.SubjectIDs, []string{"user"}) || len(owner.OrganizationIDs) != 0 {
		t.Fatalf("owner scope=%#v err=%v", owner, err)
	}
	organization, err := resolveAuditDataScope(principal, AuditPermissionGovernanceRead, now)
	if err != nil || organization.All || len(organization.SubjectIDs) != 0 || !reflect.DeepEqual(organization.OrganizationIDs, []string{"org-a", "org-b"}) {
		t.Fatalf("organization scope=%#v err=%v", organization, err)
	}
	unrestricted, err := resolveAuditDataScope(principal, AuditPermissionOperationsExport, now)
	if err != nil || !unrestricted.All || len(unrestricted.SubjectIDs) != 0 || len(unrestricted.OrganizationIDs) != 0 {
		t.Fatalf("all scope=%#v err=%v", unrestricted, err)
	}
}

func TestResolveAuditDataScopeRequiresDataPolicyForSameExactPermission(t *testing.T) {
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	principal := auditScopeTestPrincipal(now, map[string][]identitysdk.DataScope{
		AuditPermissionGovernanceRead: {identitysdk.DataScopeAll},
	})
	resource, action := splitAuditTestPermission(AuditPermissionBusinessRead)
	principal.AccessBundle.FunctionGrants = append(principal.AccessBundle.FunctionGrants, identitysdk.FunctionGrant{Resource: resource, Action: action, Effect: identitysdk.EffectAllow})
	if _, err := resolveAuditDataScope(principal, AuditPermissionBusinessRead, now); err == nil {
		t.Fatal("function grant reused another exact Permission's data policy")
	}
}

func TestResolveAuditDataScopeFailsClosedWhenOrganizationFactsAreMissing(t *testing.T) {
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	principal := auditScopeTestPrincipal(now, map[string][]identitysdk.DataScope{
		AuditPermissionGovernanceRead: {identitysdk.DataScopeOrgChild},
	})
	scope, err := resolveAuditDataScope(principal, AuditPermissionGovernanceRead, now)
	if err != nil {
		t.Fatal(err)
	}
	if scope.All || len(scope.SubjectIDs) != 0 || len(scope.OrganizationIDs) != 0 {
		t.Fatalf("missing organization facts expanded scope: %#v", scope)
	}
}

func TestResolveAuditDataScopeRejectsPredicateThatDoesNotMatchDeclaredScope(t *testing.T) {
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	principal := auditScopeTestPrincipal(now, map[string][]identitysdk.DataScope{
		AuditPermissionBusinessRead: {identitysdk.DataScopeOwner},
	})
	principal.AccessBundle.DataPolicies[0].Predicate = identitysdk.Predicate{Fact: "owner_user_id", Operator: identitysdk.OperatorEqual, Value: "other"}
	if _, err := resolveAuditDataScope(principal, AuditPermissionBusinessRead, now); err == nil {
		t.Fatal("non-canonical owner predicate expanded the declared data scope")
	}
}

func auditScopeTestPrincipal(now time.Time, permissions map[string][]identitysdk.DataScope) identitysdk.Principal {
	bundle := identitysdk.AccessBundle{
		ContractVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationRevision: "revision", ExpiresAt: now.Add(time.Hour),
		Subject: identitysdk.Subject{WorkspaceID: "workspace", SubjectID: "user"},
	}
	for permission, scopes := range permissions {
		resource, action := splitAuditTestPermission(permission)
		bundle.FunctionGrants = append(bundle.FunctionGrants, identitysdk.FunctionGrant{Resource: resource, Action: action, Effect: identitysdk.EffectAllow})
		bundle.DataPolicies = append(bundle.DataPolicies, identitysdk.DataPolicy{
			Key: "data-" + permission, Resource: resource, Action: action, Effect: identitysdk.EffectAllow,
			DataScopes: append([]identitysdk.DataScope(nil), scopes...), Predicate: auditTestScopePredicate(scopes),
		})
	}
	return identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: true, WorkspaceID: "workspace", UserID: "user",
		AuthorizationRevision: "revision", AccessBundle: &bundle,
	}
}

func splitAuditTestPermission(permission string) (identitysdk.ResourceType, identitysdk.Action) {
	separator := strings.LastIndexByte(permission, '.')
	return identitysdk.ResourceType(permission[:separator]), identitysdk.Action(permission[separator+1:])
}

func auditTestScopePredicate(scopes []identitysdk.DataScope) identitysdk.Predicate {
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
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return identitysdk.Predicate{Any: parts}
}
