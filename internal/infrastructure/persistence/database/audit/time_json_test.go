package auditstore

import (
	"strings"
	"testing"
	"time"
)

func TestAuditJSONStoresInstantsAsUnixMilliseconds(t *testing.T) {
	instant := time.Date(2026, 9, 25, 4, 5, 6, 789000000, time.UTC)
	raw, err := marshalAuditJSON(map[string]any{"created_at": instant.Format(time.RFC3339Nano), "nested": map[string]any{"updated_at": instant}})
	if err != nil {
		t.Fatal(err)
	}
	if text := string(raw); strings.Count(text, "1790309106789") != 2 {
		t.Fatalf("unexpected durable audit JSON: %s", text)
	}
	var decoded map[string]any
	if err = unmarshalAuditJSON(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["created_at"] != float64(1790309106789) {
		t.Fatalf("unexpected decoded instant: %#v", decoded)
	}
	if err = unmarshalAuditJSON([]byte(`{"created_at":"2026-09-25T04:05:06Z"}`), &decoded); err == nil {
		t.Fatal("accepted string-encoded durable audit instant")
	}
}
