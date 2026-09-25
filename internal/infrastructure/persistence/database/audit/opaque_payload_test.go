package auditstore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
)

func TestAuditOwnsNumericEventInstantButPreservesOpaquePayloads(t *testing.T) {
	db, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(db, renderer)
	instant := time.Date(2026, 9, 25, 12, 0, 0, 123_000_000, time.FixedZone("local", 8*3600))
	event := contract.Event{
		ID: "opaque-payload", WorkspaceID: "workspace", Family: contract.EventFamilyBusinessEntity,
		Event: "record.updated", ActorID: "user", CreatedAt: instant.Format(time.RFC3339Nano),
		Metadata: map[string]any{"created_at": "business-provided-label"},
		Before:   map[string]any{"updated_at": "opaque external value"},
		After:    map[string]any{"updated_at": instant.UnixMilli()},
	}
	if err := store.AppendPrepared(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	var createdAt int64
	var metadata, before, after string
	if err := db.QueryRowContext(t.Context(), `SELECT created_at,metadata_json,before_json,after_json FROM _audit_events WHERE id=?`, event.ID).Scan(&createdAt, &metadata, &before, &after); err != nil {
		t.Fatal(err)
	}
	if createdAt != instant.UnixMilli() {
		t.Fatalf("stored event instant=%d want=%d", createdAt, instant.UnixMilli())
	}
	var stored map[string]any
	for _, item := range []struct {
		raw  string
		key  string
		want any
	}{
		{metadata, "created_at", "business-provided-label"},
		{before, "updated_at", "opaque external value"},
		{after, "updated_at", float64(instant.UnixMilli())},
	} {
		if err := json.Unmarshal([]byte(item.raw), &stored); err != nil || stored[item.key] != item.want {
			t.Fatalf("stored payload=%s err=%v", item.raw, err)
		}
	}
	events, err := store.List(t.Context(), event.WorkspaceID, contract.Query{Event: event.Event})
	if err != nil || len(events) != 1 || events[0].Metadata["created_at"] != event.Metadata["created_at"] || events[0].Before["updated_at"] != event.Before["updated_at"] || events[0].After["updated_at"] != float64(instant.UnixMilli()) {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}
