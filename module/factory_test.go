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

func (h testAuditApplicationHost) ResolveAuditSurfacePrincipal(_ context.Context, request modulehost.AuditSurfacePrincipalRequest) (modulehost.AuditSurfacePrincipal, error) {
	return modulehost.AuditSurfacePrincipal{
		Identity: request.Identity, BusinessProfileKey: request.BusinessProfileKey, BusinessProfileID: request.BusinessProfileID,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, AuthorizationRevision: request.Identity.AuthorizationRevision,
	}, nil
}
func (testAuditApplicationHost) AuthorizeAuditRecord(context.Context, modulehost.AuditSurfacePrincipal, string, string) error {
	return nil
}
func (testAuditApplicationHost) ProjectAuditEvents(_ context.Context, _ modulehost.AuditSurfacePrincipal, events []contract.Event) ([]contract.Event, error) {
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

func TestAuthorizationActionsExposeGovernancePageFromSourceSurface(t *testing.T) {
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

func TestModuleOwnsAuditProductHTTPSurfaceAndOpenAPI(t *testing.T) {
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
	if descriptor := binding.Descriptor(); descriptor.Validate() != nil || !descriptor.Capabilities.HTTPSurface {
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
		t.Fatal("Audit Binding must provide HTTP surfaces")
	}
	if len(provider.HTTPSurfaces()) != 1 {
		t.Fatalf("Audit HTTP surfaces=%v", provider.HTTPSurfaces())
	}
	surface := provider.HTTPSurfaces()[0]
	if err := modulehttp.ValidateSurface(surface); err != nil {
		t.Fatal(err)
	}
	if len(surface.Routes()) != 7 || len(surface.(modulehttp.OpenAPIProvider).OpenAPIOperations()) != 7 {
		t.Fatalf("routes=%d OpenAPI=%d", len(surface.Routes()), len(surface.(modulehttp.OpenAPIProvider).OpenAPIOperations()))
	}
	expectedRoutes := map[string]struct {
		permission string
		auditClass string
	}{
		"GET /business/audit-events":                          {"audit.business.read", "business_audit_read"},
		"POST /business/audit-event-exports":                  {"audit.business.export.prepare", "business_audit_export_prepare_audit"},
		"GET /business/audit-event-exports/downloads/{token}": {"audit.business.export.download", "business_audit_export_download_audit"},
		"GET /tenant-admin/audit-events":                      {"audit.governance.read", "tenant_governance_audit_read"},
		"GET /tenant-admin/audit-events/export":               {"audit.governance.export", "tenant_governance_audit_export"},
		"GET /operations/audit-events":                        {"audit.ops.read", "operations_audit_read"},
		"GET /operations/audit-events/export":                 {"audit.ops.export", "operations_audit_export"},
	}
	operations := surface.(modulehttp.OpenAPIProvider).OpenAPIOperations()
	if method := operations["GET /business/audit-events"]["x-domainry-runtime-client-method"]; method != "listBusinessAuditEventPage" {
		t.Fatalf("business Audit Runtime client method=%v", method)
	}
	for _, route := range surface.Routes() {
		pattern := route.Pattern()
		expected, ok := expectedRoutes[pattern]
		if !ok || route.Action.Permission == nil || route.Action.Permission.Key != expected.permission || route.Action.AuditClass != expected.auditClass {
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

	request := httptest.NewRequest(http.MethodGet, "/business/audit-events", nil)
	response := httptest.NewRecorder()
	surface.Handler().ServeHTTP(response, request)
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
	request = httptest.NewRequest(http.MethodGet, "/business/audit-events?event=order.completed&page_size=20", nil)
	request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: principal}))
	response = httptest.NewRecorder()
	surface.Handler().ServeHTTP(response, request)
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

	request = httptest.NewRequest(http.MethodPost, "/business/audit-event-exports", bytes.NewBufferString(`{"filters":{},"unknown":true}`))
	request.Header.Set("Idempotency-Key", "invalid-body")
	request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: principal}))
	response = httptest.NewRecorder()
	surface.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte("backend.audit.export_request_invalid")) {
		t.Fatalf("invalid export status=%d body=%s", response.Code, response.Body.String())
	}
}

func auditHTTPTestPrincipal() identitysdk.Principal {
	permissions := []string{
		"audit.business.read", "audit.business.export", "audit.governance.read", "audit.governance.export", "audit.ops.read", "audit.ops.export",
	}
	grants := make([]identitysdk.FunctionGrant, 0, len(permissions))
	for _, permission := range permissions {
		for index := len(permission) - 1; index >= 0; index-- {
			if permission[index] == '.' {
				grants = append(grants, identitysdk.FunctionGrant{Resource: identitysdk.ResourceType(permission[:index]), Action: identitysdk.Action(permission[index+1:]), Effect: identitysdk.EffectAllow})
				break
			}
		}
	}
	bundle := identitysdk.AccessBundle{ContractVersion: identitysdk.CurrentPolicyBundleVersion, FunctionGrants: grants}
	return identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: true, WorkspaceID: "workspace", UserID: "user", RoleKey: "member", AuthorizationRevision: "r1", AccessBundle: &bundle,
	}
}
