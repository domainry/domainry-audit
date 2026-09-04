package module_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	auditsdk "github.com/domainry/domainry-audit-sdk"
	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditmodule "github.com/domainry/domainry-audit/module"
	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/modulehttp"
	identitysdk "github.com/domainry/domainry-identity-sdk"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormmigration "github.com/domainry/domainry-orm/migration"
	"github.com/domainry/domainry-orm/query"
	"github.com/domainry/domainry-orm/schema"
	_ "modernc.org/sqlite"
)

type integrationClock struct{ now time.Time }

func (c integrationClock) Now() time.Time { return c.now }

type integrationHost struct {
	database  *sql.DB
	dialect   ormdialect.Renderer
	registrar *integrationMigrationRegistrar
}

func (h integrationHost) Database() modulehost.Database             { return h.database }
func (h integrationHost) Dialect() modulehost.Dialect               { return h.dialect }
func (h integrationHost) Migrations() modulehost.MigrationRegistrar { return h.registrar }

type integrationMigrationRegistrar struct {
	database   *sql.DB
	dialect    ormdialect.Renderer
	mu         sync.Mutex
	owners     []string
	migrations [][]modulehost.SchemaMigration
}

func (*integrationMigrationRegistrar) Driver() string { return "sqlite" }
func (*integrationMigrationRegistrar) Schema() string { return "" }
func (r *integrationMigrationRegistrar) ApplyOwnedMigrations(ctx context.Context, owner string, migrations []modulehost.SchemaMigration) error {
	r.mu.Lock()
	r.owners = append(r.owners, owner)
	r.migrations = append(r.migrations, append([]modulehost.SchemaMigration(nil), migrations...))
	r.mu.Unlock()
	runner, err := ormmigration.NewRunner(r.database, r.dialect, ormmigration.Options{})
	if err != nil {
		return err
	}
	return runner.Apply(ctx, migrations)
}

type integrationTransaction struct{ *sql.Tx }

func (tx integrationTransaction) ExecContext(ctx context.Context, statement string, arguments ...any) (contract.Result, error) {
	return tx.Tx.ExecContext(ctx, statement, arguments...)
}
func (tx integrationTransaction) QueryRowContext(ctx context.Context, statement string, arguments ...any) contract.Row {
	return tx.Tx.QueryRowContext(ctx, statement, arguments...)
}

func TestIntegrationOpenModuleSubmitsSourceMigrationsToHostSingleLedger(t *testing.T) {
	database, host := openIntegrationDatabase(t)
	binding := openIntegrationModule(t, host, integrationClock{now: time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)})
	defer binding.Close(context.Background())
	descriptor := binding.Descriptor()
	if err := descriptor.Validate(); err != nil || descriptor.Mode != auditsdk.DeploymentModeModule {
		t.Fatalf("public descriptor must remain Module-only: descriptor=%+v err=%v", descriptor, err)
	}
	capabilities, ok := binding.(modulecapability.Binding)
	if !ok {
		t.Fatal("public binding does not expose its source-owned capability contract")
	}
	summary, err := capabilities.CapabilitySummary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(summary.Identity.SupportedDeploymentModes, []modulecapability.DeploymentMode{modulecapability.DeploymentModeModule}) {
		t.Fatalf("Audit capability invented a non-Module deployment mode: %v", summary.Identity.SupportedDeploymentModes)
	}

	host.registrar.mu.Lock()
	owners := append([]string(nil), host.registrar.owners...)
	submitted := append([][]modulehost.SchemaMigration(nil), host.registrar.migrations...)
	host.registrar.mu.Unlock()
	if !reflect.DeepEqual(owners, []string{"audit"}) || len(submitted) != 1 {
		t.Fatalf("host registrar calls: owners=%v submissions=%d", owners, len(submitted))
	}
	want, err := auditmodule.SchemaMigrations(host.dialect, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(submitted[0], want) || len(want) != 3 {
		t.Fatalf("submitted migrations differ from public source definitions: got=%+v want=%+v", submitted[0], want)
	}

	var versions int
	if err := database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _schema_migrations WHERE dirty = 0`).Scan(&versions); err != nil || versions != len(want) {
		t.Fatalf("host ledger completed versions=%d err=%v", versions, err)
	}
	rows, err := database.QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%schema%migration%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ledgers []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		ledgers = append(ledgers, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ledgers, []string{"_schema_migrations"}) {
		t.Fatalf("migration ledgers=%v; Audit must use only the host ledger", ledgers)
	}
}

func TestIntegrationPublicSDKAppendQueryIsImmutableWorkspaceScopedAndStable(t *testing.T) {
	_, host := openIntegrationDatabase(t)
	now := time.Date(2026, 9, 3, 2, 0, 0, 0, time.UTC)
	binding := openIntegrationModule(t, host, integrationClock{now: now})
	defer binding.Close(context.Background())

	mutable := contract.AppendRequest{
		Event: "order.updated", ObjectKey: "order", RecordID: "record-1", Summary: "original",
		Actor:    contract.Actor{WorkspaceID: "tenant-a", SubjectID: "actor-a", RoleKey: "member"},
		Metadata: map[string]any{"result": "completed"}, Before: map[string]any{"status": "pending"}, After: map[string]any{"status": "completed"},
	}
	created, err := binding.Appender().Append(t.Context(), mutable)
	if err != nil {
		t.Fatal(err)
	}
	mutable.Metadata["result"] = "tampered"
	mutable.Before["status"] = "tampered"
	mutable.After["status"] = "tampered"

	idempotent := contract.AppendRequest{
		IdempotencyKey: "request-42", Event: "order.completed", ObjectKey: "order", RecordID: "record-42", Summary: "completed once",
		Actor: contract.Actor{WorkspaceID: "tenant-a", SubjectID: "actor-a"}, Metadata: map[string]any{"result": "completed"},
	}
	first, err := binding.Appender().Append(t.Context(), idempotent)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := binding.Appender().Append(t.Context(), idempotent)
	if err != nil || replay.ID != first.ID {
		t.Fatalf("exact replay: first=%s replay=%s err=%v", first.ID, replay.ID, err)
	}
	conflict := idempotent
	conflict.Summary = "different payload"
	if _, err := binding.Appender().Append(t.Context(), conflict); err == nil {
		t.Fatal("idempotency key reuse with a different event payload was accepted")
	}
	if _, err := binding.Appender().Append(t.Context(), contract.AppendRequest{
		Event: "order.updated", ObjectKey: "order", RecordID: "foreign", Actor: contract.Actor{WorkspaceID: "tenant-b", SubjectID: "actor-b"},
	}); err != nil {
		t.Fatal(err)
	}

	events, err := binding.Reader().List(t.Context(), "tenant-a", contract.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("tenant-a events=%d, want immutable event plus one idempotent event", len(events))
	}
	byID := make(map[string]contract.Event, len(events))
	for _, event := range events {
		if event.WorkspaceID != "tenant-a" {
			t.Fatalf("cross-workspace event leaked: %+v", event)
		}
		byID[event.ID] = event
	}
	stored := byID[created.ID]
	if stored.Summary != "original" || stored.Metadata["result"] != "completed" || stored.Before["status"] != "pending" || stored.After["status"] != "completed" {
		t.Fatalf("caller mutation changed stored event: %+v", stored)
	}
	stored.Metadata["result"] = "reader-tampered"
	events, err = binding.Reader().List(t.Context(), "tenant-a", contract.Query{Event: "order.updated"})
	if err != nil || len(events) != 1 || events[0].Metadata["result"] != "completed" {
		t.Fatalf("reader mutation changed persistence: events=%+v err=%v", events, err)
	}
	resolved, err := binding.Reader().List(t.Context(), "tenant-a", contract.Query{Event: "order.completed"})
	if err != nil || len(resolved) != 1 || resolved[0].Summary != "completed once" {
		t.Fatalf("conflicting replay changed original: events=%+v err=%v", resolved, err)
	}

	createdAt := now.Add(-time.Hour).Format(time.RFC3339)
	for _, id := range []string{"event-03", "event-01", "event-05", "event-02", "event-04"} {
		if err := binding.PreparedAppender().AppendPrepared(t.Context(), contract.Event{
			ID: id, WorkspaceID: "tenant-page", Event: "order.viewed", ActorID: "actor", Metadata: map[string]any{}, CreatedAt: createdAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := binding.Reader().List(t.Context(), "tenant-page", contract.Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	page2, err := binding.Reader().List(t.Context(), "tenant-page", contract.Query{Limit: 2, Cursor: contract.EncodeCursor(page1[len(page1)-1])})
	if err != nil {
		t.Fatal(err)
	}
	page3, err := binding.Reader().List(t.Context(), "tenant-page", contract.Query{Limit: 2, Cursor: contract.EncodeCursor(page2[len(page2)-1])})
	if err != nil {
		t.Fatal(err)
	}
	if got := append(append(eventIDs(page1), eventIDs(page2)...), eventIDs(page3)...); !reflect.DeepEqual(got, []string{"event-05", "event-04", "event-03", "event-02", "event-01"}) {
		t.Fatalf("unstable keyset order across equal timestamps: %v", got)
	}
}

func TestIntegrationPublicModuleSharesCallerTransactionCommitAndRollback(t *testing.T) {
	database, host := openIntegrationDatabase(t)
	binding := openIntegrationModule(t, host, integrationClock{now: time.Date(2026, 9, 3, 3, 0, 0, 0, time.UTC)})
	defer binding.Close(context.Background())
	createHostRecordTable(t, database, host.dialect)

	commitTx, err := database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	insertHostRecord(t, commitTx, host.dialect, "committed")
	if _, err := binding.TransactionalAppender().AppendWithin(t.Context(), integrationTransaction{commitTx}, contract.AppendRequest{
		IdempotencyKey: "committed", Event: "record.created", ObjectKey: "host_record", RecordID: "committed",
		Actor: contract.Actor{WorkspaceID: "tenant-transaction", SubjectID: "actor"},
	}); err != nil {
		_ = commitTx.Rollback()
		t.Fatal(err)
	}
	if err := commitTx.Commit(); err != nil {
		t.Fatal(err)
	}

	rollbackTx, err := database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	insertHostRecord(t, rollbackTx, host.dialect, "rolled-back")
	rollbackEvent, err := binding.Factory().Build(t.Context(), contract.AppendRequest{
		IdempotencyKey: "rolled-back", Event: "record.created", ObjectKey: "host_record", RecordID: "rolled-back",
		Actor: contract.Actor{WorkspaceID: "tenant-transaction", SubjectID: "actor"},
	})
	if err != nil {
		_ = rollbackTx.Rollback()
		t.Fatal(err)
	}
	if err := auditmodule.AppendPreparedWithin(t.Context(), host.dialect, integrationTransaction{rollbackTx}, rollbackEvent); err != nil {
		_ = rollbackTx.Rollback()
		t.Fatal(err)
	}
	if err := rollbackTx.Rollback(); err != nil {
		t.Fatal(err)
	}

	if got := hostRecordIDs(t, database, host.dialect); !reflect.DeepEqual(got, []string{"committed"}) {
		t.Fatalf("host records after commit/rollback=%v", got)
	}
	events, err := binding.Reader().List(t.Context(), "tenant-transaction", contract.Query{})
	if err != nil || !reflect.DeepEqual(eventIDs(events), []string{contract.IdempotentEventID("tenant-transaction", "committed")}) {
		t.Fatalf("audit rows did not share caller transaction boundary: events=%+v err=%v", events, err)
	}
}

func TestIntegrationHTTPAdapterEnforcesTenantAndExactActionAuthorization(t *testing.T) {
	_, host := openIntegrationDatabase(t)
	now := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
	binding := openIntegrationModule(t, host, integrationClock{now: now})
	defer binding.Close(context.Background())
	for _, workspaceID := range []string{"tenant-a", "tenant-b"} {
		if _, err := binding.Appender().Append(t.Context(), contract.AppendRequest{
			Event: "identity.role.changed", ObjectKey: "role", RecordID: workspaceID,
			Actor: contract.Actor{WorkspaceID: workspaceID, SubjectID: "admin"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	binder, ok := binding.(auditsdk.ApplicationHostBinder)
	if !ok {
		t.Fatal("public binding does not expose the Module application-host seam")
	}
	if err := binder.BindApplicationHost(integrationApplicationHost{}); err != nil {
		t.Fatal(err)
	}
	provider := binding.(modulehttp.Provider)
	adapter := provider.HTTPAdapters()[0]

	wrongAction := integrationPrincipal(now, "tenant-a", "admin", "audit.business.read")
	response := serveAuditRequest(adapter, wrongAction, "/audit/governance/events")
	if response.Code != http.StatusForbidden {
		t.Fatalf("business read grant authorized governance action: status=%d body=%s", response.Code, response.Body.String())
	}

	governance := integrationPrincipal(now, "tenant-a", "admin", "audit.governance.read")
	response = serveAuditRequest(adapter, governance, "/audit/governance/events")
	if response.Code != http.StatusOK {
		t.Fatalf("governance request failed: status=%d body=%s", response.Code, response.Body.String())
	}
	var page struct {
		Items []struct {
			RecordID string `json:"record_id"`
		} `json:"items"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Count != 1 || len(page.Items) != 1 || page.Items[0].RecordID != "tenant-a" {
		t.Fatalf("tenant-scoped governance response=%+v", page)
	}
}

func TestIntegrationConcurrentIdempotentAppendConverges(t *testing.T) {
	_, host := openIntegrationDatabase(t)
	binding := openIntegrationModule(t, host, integrationClock{now: time.Date(2026, 9, 3, 5, 0, 0, 0, time.UTC)})
	defer binding.Close(context.Background())

	request := contract.AppendRequest{
		IdempotencyKey: "concurrent-request", Event: "invoice.paid", ObjectKey: "invoice", RecordID: "invoice-1", Summary: "paid",
		Actor: contract.Actor{WorkspaceID: "tenant-concurrent", SubjectID: "actor"}, Metadata: map[string]any{"result": "completed"},
	}
	const workers = 24
	start := make(chan struct{})
	results := make(chan struct {
		id  string
		err error
	}, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			event, err := binding.Appender().Append(context.Background(), request)
			results <- struct {
				id  string
				err error
			}{id: event.ID, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	wantID := contract.IdempotentEventID("tenant-concurrent", "concurrent-request")
	for result := range results {
		if result.err != nil || result.id != wantID {
			t.Errorf("concurrent replay id=%q err=%v", result.id, result.err)
		}
	}
	events, err := binding.Reader().List(t.Context(), "tenant-concurrent", contract.Query{})
	if err != nil || len(events) != 1 || events[0].ID != wantID {
		t.Fatalf("concurrent replay persistence: events=%+v err=%v", events, err)
	}
}

type integrationApplicationHost struct{}

func (integrationApplicationHost) ResolveAuditPrincipal(_ context.Context, request modulehost.AuditPrincipalRequest) (modulehost.AuditPrincipal, error) {
	return modulehost.AuditPrincipal{
		Identity: request.Identity, BusinessProfileKey: request.BusinessProfileKey, BusinessProfileID: request.BusinessProfileID,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, AuthorizationRevision: request.Identity.AuthorizationRevision,
	}, nil
}
func (integrationApplicationHost) AuthorizeAuditRecord(context.Context, modulehost.AuditPrincipal, string, string) error {
	return nil
}
func (integrationApplicationHost) ProjectAuditEvents(_ context.Context, _ modulehost.AuditPrincipal, events []contract.Event) ([]contract.Event, error) {
	return append([]contract.Event(nil), events...), nil
}
func (integrationApplicationHost) AuditExportTokenKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func openIntegrationDatabase(t *testing.T) (*sql.DB, integrationHost) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit-integration.db")
	database, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)", filepath.ToSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(8)
	database.SetMaxIdleConns(8)
	t.Cleanup(func() { _ = database.Close() })
	if err := database.PingContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	dialect, err := ormdialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	registrar := &integrationMigrationRegistrar{database: database, dialect: dialect}
	return database, integrationHost{database: database, dialect: dialect, registrar: registrar}
}

func openIntegrationModule(t *testing.T, host integrationHost, clock integrationClock) auditsdk.Binding {
	t.Helper()
	binding, err := auditmodule.NewFactory(auditmodule.Options{Clock: clock}).OpenModule(t.Context(), auditsdk.ApplicationRef{InstallationID: "integration-test"}, host)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func eventIDs(events []contract.Event) []string {
	result := make([]string, len(events))
	for index := range events {
		result[index] = events[index].ID
	}
	return result
}

func createHostRecordTable(t *testing.T, database *sql.DB, renderer ormdialect.Renderer) {
	t.Helper()
	statement, arguments, err := schema.NewTable(renderer, "_host_records").Columns(
		schema.Column("id", schema.TextKey(191)).NotNull(),
	).PrimaryKey("id").Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
}

func insertHostRecord(t *testing.T, transaction *sql.Tx, renderer ormdialect.Renderer, id string) {
	t.Helper()
	statement, arguments, err := query.NewInsertBuilder(renderer, "_host_records").Columns("id").Values(id).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.ExecContext(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
}

func hostRecordIDs(t *testing.T, database *sql.DB, renderer ormdialect.Renderer) []string {
	t.Helper()
	statement, arguments, err := query.NewSelectBuilder(renderer, "_host_records").Columns("id").OrderBy(query.Ascending("id")).Build()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := database.QueryContext(t.Context(), statement, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func integrationPrincipal(now time.Time, workspaceID, userID, permission string) identitysdk.Principal {
	resource, action, found := splitPermission(permission)
	if !found {
		panic("invalid test permission: " + permission)
	}
	bundle := identitysdk.AccessBundle{
		ContractVersion: identitysdk.CurrentPolicyBundleVersion, AuthorizationRevision: "revision", ExpiresAt: now.Add(time.Hour),
		Subject:        identitysdk.Subject{WorkspaceID: identitysdk.WorkspaceID(workspaceID), SubjectID: identitysdk.SubjectID(userID)},
		FunctionGrants: []identitysdk.FunctionGrant{{Resource: resource, Action: action, Effect: identitysdk.EffectAllow}},
		DataPolicies: []identitysdk.DataPolicy{{
			Key: "data-" + permission, Resource: resource, Action: action, Effect: identitysdk.EffectAllow,
			DataScopes: []identitysdk.DataScope{identitysdk.DataScopeAll}, Predicate: identitysdk.Predicate{},
		}},
	}
	return identitysdk.Principal{
		ContractVersion: identitysdk.PrincipalContextContractVersion, Known: true, WorkspaceID: workspaceID, UserID: userID,
		AuthorizationRevision: "revision", AccessBundle: &bundle,
	}
}

func splitPermission(permission string) (identitysdk.ResourceType, identitysdk.Action, bool) {
	for index := len(permission) - 1; index >= 0; index-- {
		if permission[index] == '.' {
			return identitysdk.ResourceType(permission[:index]), identitysdk.Action(permission[index+1:]), true
		}
	}
	return "", "", false
}

func serveAuditRequest(adapter modulehttp.Adapter, principal identitysdk.Principal, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request = request.WithContext(identitysdk.WithRequestIdentity(request.Context(), identitysdk.RequestIdentity{Principal: principal}))
	response := httptest.NewRecorder()
	adapter.Handler().ServeHTTP(response, request)
	return response
}
