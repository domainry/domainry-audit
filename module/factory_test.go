package module

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	actioncontract "github.com/domainry/domainry-foundation/action"
	"github.com/domainry/domainry-foundation/modulehttp"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormmigration "github.com/domainry/domainry-orm/migration"
	_ "modernc.org/sqlite"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type testHost struct {
	database modulehost.Database
	dialect  modulehost.Dialect
}

func newTestHost(t *testing.T, db *sql.DB) testHost {
	t.Helper()
	dialect, err := ormdialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return testHost{database: db, dialect: dialect}
}
func (h testHost) Database() modulehost.Database             { return h.database }
func (h testHost) Dialect() modulehost.Dialect               { return h.dialect }
func (h testHost) Migrations() modulehost.MigrationRegistrar { return testMigrationRegistrar{host: h} }

type testMigrationRegistrar struct{ host testHost }

func (testMigrationRegistrar) Driver() string { return "sqlite" }
func (testMigrationRegistrar) Schema() string { return "" }
func (r testMigrationRegistrar) ApplyOwnedMigrations(ctx context.Context, _ string, migrations []modulehost.SchemaMigration) error {
	runner, err := ormmigration.NewRunner(r.host.database, r.host.dialect, ormmigration.Options{})
	if err != nil {
		return err
	}
	return runner.Apply(ctx, migrations)
}

type testTransaction struct{ *sql.Tx }

func (t testTransaction) ExecContext(ctx context.Context, q string, args ...any) (contract.Result, error) {
	return t.Tx.ExecContext(ctx, q, args...)
}
func (t testTransaction) QueryRowContext(ctx context.Context, q string, args ...any) contract.Row {
	return t.Tx.QueryRowContext(ctx, q, args...)
}

type testAuditApplicationHost struct{ key []byte }

func (h testAuditApplicationHost) ResolveAuditPrincipal(_ context.Context, request modulehost.AuditPrincipalRequest) (modulehost.AuditPrincipal, error) {
	return modulehost.AuditPrincipal{
		Identity: request.Identity, BusinessProfileKey: request.BusinessProfileKey, BusinessProfileID: request.BusinessProfileID,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, AuthorizationRevision: request.Identity.AuthorizationRevision,
	}, nil
}
func (testAuditApplicationHost) AuthorizeAuditRecord(context.Context, modulehost.AuditPrincipal, string, string) error {
	return nil
}
func (testAuditApplicationHost) ProjectAuditEvents(_ context.Context, _ modulehost.AuditPrincipal, events []contract.Event) ([]contract.Event, error) {
	return append([]contract.Event(nil), events...), nil
}
func (h testAuditApplicationHost) AuditExportTokenKey() []byte { return append([]byte(nil), h.key...) }

func TestModuleUsesBorrowedHostDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	binding, err := NewFactory(Options{}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = binding.Appender().Append(t.Context(), contract.AppendRequest{Event: "record.updated", ObjectKey: "record", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user"}}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM _audit_events`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM _audit_export_artifacts`).Scan(&count); err != nil {
		t.Fatalf("neutral Audit export artifact table is missing: %v", err)
	}
	if err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM business__audit_export_artifacts`).Scan(&count); err == nil {
		t.Fatal("legacy Runtime-specific Audit export table must not be created")
	}
}

func TestAuthorizationActionsExposeGovernancePageFromSourceAdapter(t *testing.T) {
	actions := AuthorizationActions()
	found := false
	for _, action := range actions {
		if action.Key != "audit.governance.read" {
			continue
		}
		found = action.Permission != nil && action.Permission.Key == action.Key && len(action.Pages) == 1 && action.Pages[0].Route == "/admin/system/audit"
	}
	if !found {
		t.Fatalf("governance page Action missing from source projection: %#v", actions)
	}
	actions[0].Key = "mutated"
	if next := AuthorizationActions(); len(next) == 0 || next[0].Key == "mutated" {
		t.Fatal("AuthorizationActions leaked mutable source state")
	}
}

func TestTransactionalAppendClassificationReplayAndSubjectLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	binding, err := NewFactory(Options{}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.AppendRequest{Event: "identity.role.changed", ObjectKey: "role", IdempotencyKey: "one", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user"}}
	if _, err = binding.TransactionalAppender().AppendWithin(t.Context(), testTransaction{tx}, request); err != nil {
		t.Fatal(err)
	}
	if _, err = binding.TransactionalAppender().AppendWithin(t.Context(), testTransaction{tx}, request); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	events, err := binding.Reader().List(t.Context(), "workspace", contract.Query{Class: contract.EventClassGovernance})
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	preview, err := binding.SubjectLifecycle().PreviewSubject(t.Context(), "workspace", "user")
	if err != nil || string(preview) != `{"audit_references":1}` {
		t.Fatalf("preview=%s err=%v", preview, err)
	}
	if _, err = binding.SubjectLifecycle().EraseSubject(t.Context(), "workspace", "user"); err != nil {
		t.Fatal(err)
	}
	events, err = binding.Reader().List(t.Context(), "workspace", contract.Query{})
	if err != nil || len(events) != 1 || events[0].ActorID == "user" {
		t.Fatalf("events=%v err=%v", events, err)
	}
}

func TestBusinessExportLifecycleIsOwnedByModule(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	binding, err := NewFactory(Options{Clock: fixedClock{now}}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	_, err = binding.Appender().Append(t.Context(), contract.AppendRequest{Event: "order.completed", ObjectKey: "order", RecordID: "one", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user", RoleKey: "member"}, Metadata: map[string]any{"result": "completed"}})
	if err != nil {
		t.Fatal(err)
	}
	binding.Exporter().ConfigureExport([]byte("0123456789abcdef0123456789abcdef"), nil)
	principal := contract.ExportPrincipal{WorkspaceID: "workspace", UserID: "user", RoleKey: "member", AuthorizationRevision: "r1"}
	prepared, err := binding.Exporter().PrepareExport(t.Context(), contract.ExportRequest{}, "idem-1", principal)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := binding.Exporter().PrepareExport(t.Context(), contract.ExportRequest{}, "idem-1", principal)
	if err != nil || replayed.ID != prepared.ID {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	content, filename, err := binding.Exporter().DownloadExport(t.Context(), prepared.DownloadToken, principal)
	if err != nil || len(content) == 0 || filename == "" {
		t.Fatalf("filename=%q content=%d err=%v", filename, len(content), err)
	}
	if _, _, err = binding.Exporter().DownloadExport(t.Context(), prepared.DownloadToken, contract.ExportPrincipal{WorkspaceID: "workspace", UserID: "other", RoleKey: "member", AuthorizationRevision: "r1"}); err == nil {
		t.Fatal("requester mismatch accepted")
	}
}

func TestModuleOwnsAuditProductHTTPAdapterAndOpenAPI(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	binding, err := NewFactory(Options{Clock: fixedClock{now}}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if descriptor := binding.Descriptor(); descriptor.Validate() != nil || !descriptor.Capabilities.HTTPAdapter {
		t.Fatalf("Audit HTTP descriptor=%#v", descriptor)
	}
	binder, ok := binding.(auditsdk.ApplicationHostBinder)
	if !ok {
		t.Fatal("Audit Binding must accept its application host")
	}
	if err := binder.BindApplicationHost(testAuditApplicationHost{key: []byte("0123456789abcdef0123456789abcdef")}); err != nil {
		t.Fatal(err)
	}
	provider, ok := binding.(modulehttp.Provider)
	if !ok {
		t.Fatal("Audit Binding must provide HTTP adapters")
	}
	if len(provider.HTTPAdapters()) != 1 {
		t.Fatalf("Audit HTTP adapters=%v", provider.HTTPAdapters())
	}
	adapter := provider.HTTPAdapters()[0]
	if err := modulehttp.ValidateAdapter(adapter); err != nil {
		t.Fatal(err)
	}
	if len(adapter.Routes()) != 7 || len(adapter.(modulehttp.OpenAPIProvider).OpenAPIOperations()) != 7 {
		t.Fatalf("routes=%d OpenAPI=%d", len(adapter.Routes()), len(adapter.(modulehttp.OpenAPIProvider).OpenAPIOperations()))
	}
	expectedRoutes := map[string]struct {
		permission string
		auditClass string
	}{
		"GET /audit/events":                    {"audit.business.read", "business_audit_read"},
		"POST /audit/exports":                  {"audit.business.export.prepare", "business_audit_export_prepare_audit"},
		"GET /audit/exports/downloads/{token}": {"audit.business.export.download", "business_audit_export_download_audit"},
		"GET /audit/governance/events":         {"audit.governance.read", "tenant_governance_audit_read"},
		"GET /audit/governance/events/export":  {"audit.governance.export", "tenant_governance_audit_export"},
		"GET /audit/system/events":             {"audit.ops.read", "operations_audit_read"},
		"GET /audit/system/events/export":      {"audit.ops.export", "operations_audit_export"},
	}
	operations := adapter.(modulehttp.OpenAPIProvider).OpenAPIOperations()
	if method := operations["GET /audit/events"]["x-domainry-runtime-client-method"]; method != "listBusinessAuditEventPage" {
		t.Fatalf("business Audit Runtime client method=%v", method)
	}
	for _, route := range adapter.Routes() {
		pattern := route.Pattern()
		expected, ok := expectedRoutes[pattern]
		if !ok || route.Action.Authorization.Strategy != actioncontract.AuthorizationAuthenticated || route.Action.Permission == nil || route.Action.Permission.Key != expected.permission || route.Action.AuditClass != expected.auditClass {
			t.Fatalf("unexpected Audit route contract: %#v", route)
		}
		if operations[pattern] == nil {
			t.Fatalf("Audit route %q has no owner OpenAPI operation", pattern)
		}
		delete(expectedRoutes, pattern)
	}
	if len(expectedRoutes) != 0 {
		t.Fatalf("missing Audit routes: %#v", expectedRoutes)
	}

	request := httptest.NewRequest(http.MethodGet, "/audit/events", nil)
	response := httptest.NewRecorder()
	adapter.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !bytes.Contains(response.Body.Bytes(), []byte("backend.auth.token_required")) {
		t.Fatalf("unauthenticated status=%d body=%s", response.Code, response.Body.String())
	}

	_, err = binding.Appender().Append(t.Context(), contract.AppendRequest{
		Event: "order.completed", ObjectKey: "order", RecordID: "one",
		Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user", RoleKey: "member"}, Summary: "completed",
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auditHTTPTestPrincipal()
	request = httptest.NewRequest(http.MethodGet, "/audit/events?event=order.completed&page_size=20", nil)
	request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: principal}))
	response = httptest.NewRecorder()
	adapter.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	var page struct {
		Items []map[string]any `json:"items"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || page.Count != 1 || len(page.Items) != 1 || page.Items[0]["id"] == "" {
		t.Fatalf("page=%#v err=%v", page, err)
	}

	request = httptest.NewRequest(http.MethodPost, "/audit/exports", bytes.NewBufferString(`{"filters":{},"unknown":true}`))
	request.Header.Set("Idempotency-Key", "invalid-body")
	request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: principal}))
	response = httptest.NewRecorder()
	adapter.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte("backend.audit.export_request_invalid")) {
		t.Fatalf("invalid export status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAuditHTTPAdapterKeepsExactPermissionDataScopesIndependent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	binding, err := NewFactory(Options{Clock: fixedClock{now}}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "test"}, newTestHost(t, db))
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []contract.AppendRequest{
		{Event: "order.completed", ObjectKey: "order", RecordID: "one", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user"}},
		{Event: "order.completed", ObjectKey: "order", RecordID: "two", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "other"}},
		{Event: "identity.role.changed", ObjectKey: "role", RecordID: "one", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "user"}},
		{Event: "identity.role.changed", ObjectKey: "role", RecordID: "two", Actor: contract.Actor{WorkspaceID: "workspace", SubjectID: "other"}},
	} {
		if _, err := binding.Appender().Append(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	binder := binding.(auditsdk.ApplicationHostBinder)
	if err := binder.BindApplicationHost(testAuditApplicationHost{key: []byte("0123456789abcdef0123456789abcdef")}); err != nil {
		t.Fatal(err)
	}
	adapter := binding.(modulehttp.Provider).HTTPAdapters()[0]
	principal := auditHTTPTestPrincipalWithScopes("user", map[string][]identitysdk.DataScope{
		"audit.business.read":   {identitysdk.DataScopeOwner},
		"audit.governance.read": {identitysdk.DataScopeAll},
	})

	request := httptest.NewRequest(http.MethodGet, "/audit/events?actor_id=other", nil)
	request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: principal}))
	response := httptest.NewRecorder()
	adapter.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("business status=%d body=%s", response.Code, response.Body.String())
	}
	var businessPage struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &businessPage); err != nil || businessPage.Count != 0 {
		t.Fatalf("owner business page=%#v err=%v", businessPage, err)
	}

	request = httptest.NewRequest(http.MethodGet, "/audit/governance/events", nil)
	request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: principal}))
	response = httptest.NewRecorder()
	adapter.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("governance status=%d body=%s", response.Code, response.Body.String())
	}
	var governancePage struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &governancePage); err != nil || governancePage.Count != 2 {
		t.Fatalf("all governance page=%#v err=%v", governancePage, err)
	}
}

func auditHTTPTestPrincipal() identitysdk.Principal {
	return auditHTTPTestPrincipalWithScopes("user", map[string][]identitysdk.DataScope{
		"audit.business.read":            {identitysdk.DataScopeAll},
		"audit.business.export.prepare":  {identitysdk.DataScopeAll},
		"audit.business.export.download": {identitysdk.DataScopeAll},
		"audit.governance.read":          {identitysdk.DataScopeAll},
		"audit.governance.export":        {identitysdk.DataScopeAll},
		"audit.ops.read":                 {identitysdk.DataScopeAll},
		"audit.ops.export":               {identitysdk.DataScopeAll},
	})
}

func auditHTTPTestPrincipalWithScopes(userID string, permissions map[string][]identitysdk.DataScope) identitysdk.Principal {
	grants := make([]identitysdk.FunctionGrant, 0, len(permissions))
	policies := make([]identitysdk.DataPolicy, 0, len(permissions))
	for permission, scopes := range permissions {
		for index := len(permission) - 1; index >= 0; index-- {
			if permission[index] != '.' {
				continue
			}
			resource, action := identitysdk.ResourceType(permission[:index]), identitysdk.Action(permission[index+1:])
			grants = append(grants, identitysdk.FunctionGrant{Resource: resource, Action: action, Effect: identitysdk.EffectAllow})
			policies = append(policies, identitysdk.DataPolicy{Key: "data-" + permission, Resource: resource, Action: action, Effect: identitysdk.EffectAllow, DataScopes: append([]identitysdk.DataScope(nil), scopes...), Predicate: auditHTTPTestScopePredicate(scopes)})
			break
		}
	}
	bundle := identitysdk.AccessBundle{
		ContractVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationRevision: "r1", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Subject: identitysdk.Subject{WorkspaceID: "workspace", SubjectID: identitysdk.SubjectID(userID)}, FunctionGrants: grants, DataPolicies: policies,
	}
	return identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: true, WorkspaceID: "workspace", UserID: userID, RoleKey: "member", AuthorizationRevision: "r1", AccessBundle: &bundle,
	}
}

func auditHTTPTestScopePredicate(scopes []identitysdk.DataScope) identitysdk.Predicate {
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
