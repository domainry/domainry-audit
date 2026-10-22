package auditstore

import (
	"encoding/json"
	"testing"
)

func TestSubjectExportSeparatesPhysicalAndBusinessIDs(t *testing.T) {
	db, renderer := openAuditStoreTestDatabase(t)
	store := NewStore(db, renderer)
	appendAuditStoreTestEvent(t, store, "exported", "workspace", "subject", "")
	appendAuditStoreTestEvent(t, store, "other-actor", "workspace", "other", "")
	appendAuditStoreTestEvent(t, store, "other-workspace", "other-workspace", "subject", "")
	raw, err := store.ExportSubject(t.Context(), "workspace", "subject")
	if err != nil {
		t.Fatal(err)
	}
	var items []struct {
		ID           int64  `json:"id"`
		AuditEventID string `json:"audit_event_id"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID <= 0 || items[0].AuditEventID != auditStoreTestEventID("exported") {
		t.Fatalf("export=%s", raw)
	}
}
