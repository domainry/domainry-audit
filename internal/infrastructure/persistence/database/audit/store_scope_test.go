package auditstore

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormmigration "github.com/domainry/domainry-orm/migration"
	_ "modernc.org/sqlite"
)

type auditCaptureDatabase struct {
	*sql.DB
	lastQuery string
}

func (database *auditCaptureDatabase) QueryContext(ctx context.Context, statement string, args ...any) (*sql.Rows, error) {
	database.lastQuery = statement
	return database.DB.QueryContext(ctx, statement, args...)
}

func TestListWithinDataScopePushesOwnerAndOrganizationIntoSQL(t *testing.T) {
	database, renderer := openAuditStoreTestDatabase(t)
	capture := &auditCaptureDatabase{DB: database}
	store := NewStore(capture, renderer)
	appendAuditStoreTestEvent(t, store, "one", "workspace", "user", "org-a")
	appendAuditStoreTestEvent(t, store, "two", "workspace", "other", "org-b")
	appendAuditStoreTestEvent(t, store, "three", "workspace", "other", "")
	appendAuditStoreTestEvent(t, store, "foreign", "other-workspace", "user", "org-a")

	owner := auditrepository.OwnerDataScope("user")
	events, err := store.ListWithinDataScope(t.Context(), "workspace", contract.Query{}, owner)
	if err != nil || len(events) != 1 || events[0].ID != "one" {
		t.Fatalf("owner events=%#v err=%v", events, err)
	}
	ownerWhere := auditStoreTestWhere(capture.lastQuery)
	if !strings.Contains(ownerWhere, "actor_id") || strings.Contains(ownerWhere, "actor_org_id") {
		t.Fatalf("owner range was not pushed into SQL: %s", capture.lastQuery)
	}

	organization := auditrepository.DataScope{OrganizationIDs: []string{"org-a"}}
	events, err = store.ListWithinDataScope(t.Context(), "workspace", contract.Query{}, organization)
	if err != nil || len(events) != 1 || events[0].ID != "one" {
		t.Fatalf("organization events=%#v err=%v", events, err)
	}
	if !strings.Contains(auditStoreTestWhere(capture.lastQuery), "actor_org_id") {
		t.Fatalf("organization range was not pushed into SQL: %s", capture.lastQuery)
	}

	events, err = store.ListWithinDataScope(t.Context(), "workspace", contract.Query{ActorID: "other"}, owner)
	if err != nil || len(events) != 0 {
		t.Fatalf("caller actor filter bypassed owner scope: events=%#v err=%v", events, err)
	}

	events, err = store.ListWithinDataScope(t.Context(), "workspace", contract.Query{}, auditrepository.AllDataScope())
	if err != nil || len(events) != 3 {
		t.Fatalf("all events=%#v err=%v", events, err)
	}
	allWhere := auditStoreTestWhere(capture.lastQuery)
	if strings.Contains(allWhere, "actor_org_id") || strings.Contains(allWhere, "actor_id") {
		t.Fatalf("all added a range WHERE: %s", capture.lastQuery)
	}
}

func TestListWithinOrganizationScopeFailsClosedWithoutActorOrganizationEvidence(t *testing.T) {
	database, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(database, renderer)
	appendAuditStoreTestEvent(t, store, "missing", "workspace", "user", "")
	events, err := store.ListWithinDataScope(t.Context(), "workspace", contract.Query{}, auditrepository.DataScope{OrganizationIDs: []string{"org-a"}})
	if err != nil || len(events) != 0 {
		t.Fatalf("missing actor organization evidence was visible: events=%#v err=%v", events, err)
	}
}

func TestIdempotentReplayAcceptsMissingOptionalActorOrganization(t *testing.T) {
	database, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(database, renderer)
	event := contract.Event{ID: "without-org", WorkspaceID: "workspace", Family: contract.EventFamilyBusinessEntity, Event: "order.updated", ActorID: "user", Metadata: map[string]any{}, CreatedAt: "2026-09-03T00:00:00Z"}
	if err := store.AppendPrepared(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `UPDATE _audit_events SET actor_org_id = NULL WHERE workspace_id = 'workspace' AND id = 'without-org'`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPrepared(t.Context(), event); err != nil {
		t.Fatalf("missing optional actor organization broke exact replay: %v", err)
	}
}

func TestCorrelationIdentitiesPersistFilterAndParticipateInExactReplay(t *testing.T) {
	database, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(database, renderer)
	event := contract.Event{
		ID: "correlated", WorkspaceID: "workspace", OperationID: "operation-1", CausationID: "cause-1", OwnerRunID: "workflow-1",
		Family: contract.EventFamilyBusinessEntity, Event: "order.updated", ActorID: "user", Metadata: map[string]any{}, CreatedAt: "2026-09-03T00:00:00Z",
	}
	if err := store.AppendPrepared(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	for name, queryValue := range map[string]contract.Query{
		"operation": {OperationID: "operation-1"},
		"causation": {CausationID: "cause-1"},
		"owner run": {OwnerRunID: "workflow-1"},
	} {
		events, err := store.List(t.Context(), "workspace", queryValue)
		if err != nil || len(events) != 1 || events[0].ID != event.ID || events[0].OperationID != event.OperationID || events[0].CausationID != event.CausationID || events[0].OwnerRunID != event.OwnerRunID {
			t.Fatalf("%s filter events=%#v err=%v", name, events, err)
		}
	}
	conflict := event
	conflict.OperationID = "operation-2"
	if err := store.AppendPrepared(t.Context(), conflict); err == nil {
		t.Fatal("changed operation identity was accepted as an exact replay")
	}
}

func TestEraseSubjectIsAtomicAcrossAllMatchingAuditEvents(t *testing.T) {
	database, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(database, renderer)
	appendAuditStoreTestEvent(t, store, "one", "workspace", "user", "")
	appendAuditStoreTestEvent(t, store, "two", "workspace", "user", "")
	if _, err := database.ExecContext(t.Context(), `CREATE TRIGGER reject_second_audit_erase BEFORE UPDATE OF actor_id ON _audit_events WHEN OLD.id = 'two' BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EraseSubject(t.Context(), "workspace", "user"); err == nil {
		t.Fatal("injected batch failure was accepted")
	}
	var unchanged int
	if err := database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM _audit_events WHERE workspace_id = 'workspace' AND actor_id = 'user'`).Scan(&unchanged); err != nil || unchanged != 2 {
		t.Fatalf("subject anonymization partially committed: unchanged=%d err=%v", unchanged, err)
	}
}

func TestListSystemClassMatchesContractAuthenticationRules(t *testing.T) {
	database, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(database, renderer)
	events := []contract.Event{
		{ID: "auth-exact", WorkspaceID: "workspace", Family: contract.EventFamilyRuntimeSecurity, Event: "auth", ObjectKey: "session", CreatedAt: "2026-09-03T00:00:01Z"},
		{ID: "auth-prefix", WorkspaceID: "workspace", Family: contract.EventFamilyRuntimeSecurity, Event: "auth_workspace_denied", ObjectKey: "http_request", CreatedAt: "2026-09-03T00:00:02Z"},
		{ID: "authentication-prefix", WorkspaceID: "workspace", Family: contract.EventFamilyIdentitySecurity, Event: "authentication.denied", ObjectKey: "http_request", CreatedAt: "2026-09-03T00:00:03Z"},
		{ID: "oauth-governance", WorkspaceID: "workspace", Family: contract.EventFamilyIdentityGovernance, Event: "oauth_connection_updated", ObjectKey: "connection", CreatedAt: "2026-09-03T00:00:04Z"},
		{ID: "export-conflict", WorkspaceID: "workspace", Family: contract.EventFamilyAuditExport, Event: "audit_export_conflict", ObjectKey: "audit_events", Metadata: map[string]any{"artifact_id": "artifact", "result": "conflict", "reason": "fingerprint"}, CreatedAt: "2026-09-03T00:00:05Z"},
	}
	for _, event := range events {
		if err := store.AppendPrepared(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}

	operations, err := store.ListSystem(t.Context(), contract.Query{Class: contract.EventClassOperations})
	if err != nil {
		t.Fatal(err)
	}
	assertAuditStoreEventIDs(t, operations, "export-conflict", "authentication-prefix", "auth-prefix", "auth-exact")

	governance, err := store.ListSystem(t.Context(), contract.Query{Class: contract.EventClassGovernance})
	if err != nil {
		t.Fatal(err)
	}
	assertAuditStoreEventIDs(t, governance, "oauth-governance")
}

func TestOperationsClassUsesRegisteredFamilies(t *testing.T) {
	families := contract.EventFamiliesForClass(contract.EventClassOperations)
	if !slices.Contains(families, contract.EventFamilyAuditExport) || !slices.Contains(families, contract.EventFamilyRuntimeSecurity) {
		t.Fatalf("operations families=%v", families)
	}
}

func openAuditStoreTestDatabase(t *testing.T) (*sql.DB, ormdialect.Renderer) {
	t.Helper()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	renderer, err := ormdialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := auditpersistence.SchemaMigrations(renderer, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := ormmigration.NewRunner(database, renderer, ormmigration.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Apply(t.Context(), migrations); err != nil {
		t.Fatal(err)
	}
	return database, renderer
}

func appendAuditStoreTestEvent(t *testing.T, store *Store, id, workspaceID, actorID, actorOrgID string) {
	t.Helper()
	metadata := map[string]any{}
	if actorOrgID != "" {
		metadata["actor_org_id"] = actorOrgID
	}
	if err := store.AppendPrepared(t.Context(), contract.Event{ID: id, WorkspaceID: workspaceID, Family: contract.EventFamilyBusinessEntity, Event: "order.updated", ActorID: actorID, Metadata: metadata, CreatedAt: "2026-09-03T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
}

func auditStoreTestWhere(statement string) string {
	_, where, _ := strings.Cut(statement, " WHERE ")
	return where
}

func assertAuditStoreEventIDs(t *testing.T, events []contract.Event, want ...string) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("event ids=%v want=%v", auditStoreEventIDs(events), want)
	}
	for index := range want {
		if events[index].ID != want[index] {
			t.Fatalf("event ids=%v want=%v", auditStoreEventIDs(events), want)
		}
	}
}

func auditStoreEventIDs(events []contract.Event) []string {
	ids := make([]string, len(events))
	for index := range events {
		ids[index] = events[index].ID
	}
	return ids
}
