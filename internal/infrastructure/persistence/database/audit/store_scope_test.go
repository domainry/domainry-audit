package auditstore

import (
	"context"
	"database/sql"
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

func TestIdempotentReplayAcceptsPreScopeMigrationNullActorOrganization(t *testing.T) {
	database, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(database, renderer)
	event := contract.Event{ID: "legacy", WorkspaceID: "workspace", Event: "order.updated", ActorID: "user", Metadata: map[string]any{}, CreatedAt: "2026-09-03T00:00:00Z"}
	if err := store.AppendPrepared(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `UPDATE _audit_events SET actor_org_id = NULL WHERE workspace_id = 'workspace' AND id = 'legacy'`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendPrepared(t.Context(), event); err != nil {
		t.Fatalf("legacy null actor organization broke exact replay: %v", err)
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
	if err := store.AppendPrepared(t.Context(), contract.Event{ID: id, WorkspaceID: workspaceID, Event: "order.updated", ActorID: actorID, Metadata: metadata, CreatedAt: "2026-09-03T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
}

func auditStoreTestWhere(statement string) string {
	_, where, _ := strings.Cut(statement, " WHERE ")
	return where
}
