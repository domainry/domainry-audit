package auditstore

import (
	"github.com/domainry/domainry-audit-sdk/contract"
	"strings"
	"testing"
)

func TestSubjectErasureClearsHistoricalSnapshotsForDeclaredResources(t *testing.T) {
	db, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(db, renderer)
	for _, item := range []struct{ id, workspace, actor, record string }{
		{"actor", "workspace", "subject", "unrelated"},
		{"record", "workspace", "administrator", "member-one"},
		{"other", "workspace", "administrator", "member-other"},
		{"workspace", "other-workspace", "subject", "member-one"},
	} {
		event := contract.Event{ID: item.id, WorkspaceID: item.workspace, Event: "member.updated", ObjectKey: "member", RecordID: item.record, ActorID: item.actor, Summary: "PRIVATE NAME", Metadata: map[string]any{"email": "private@example.test"}, Before: map[string]any{"phone": "PRIVATE PHONE"}, After: map[string]any{"name": "PRIVATE NAME"}, CreatedAt: "2026-09-14T00:00:00Z"}
		if err := store.AppendPrepared(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	resources := []contract.SubjectResource{{ObjectKey: "member", RecordID: "member-one"}}
	for range 2 {
		if _, err := store.EraseSubjectResources(t.Context(), "workspace", "subject", resources); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"actor", "record", "other", "workspace"} {
		var summary, metadata, before, after, actor string
		if err := db.QueryRowContext(t.Context(), `SELECT summary,metadata_json,before_json,after_json,actor_id FROM _audit_events WHERE id=?`, id).Scan(&summary, &metadata, &before, &after, &actor); err != nil {
			t.Fatal(err)
		}
		if id == "actor" || id == "record" {
			if strings.Contains(summary+metadata+before+after, "PRIVATE") || strings.Contains(metadata, "private@example.test") {
				t.Fatalf("historical personal data remains for %s", id)
			}
			if id == "actor" && actor == "subject" {
				t.Fatal("actor remains")
			}
		} else if !strings.Contains(summary+before+after, "PRIVATE") {
			t.Fatalf("unrelated audit changed for %s", id)
		}
	}
}
