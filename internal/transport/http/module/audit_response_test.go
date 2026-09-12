package module

import (
	"encoding/json"
	"testing"

	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	auditservice "github.com/domainry/domainry-audit/internal/domain/audit/service"
)

func TestEveryAuditResponsePublishesTheSameTraceFields(t *testing.T) {
	result := auditapp.AuditQueryResult{Items: []auditservice.QueryEvent{{
		ID: "event-1", Event: "order_failed", ObjectKey: "order", RecordID: "order-1",
		ActorID: "user-1", RoleKey: "manager", RequestID: "request-1", Result: "failed", Reason: "policy_denied",
		Summary: "Order failed", Metadata: map[string]any{"safe": true}, Before: map[string]any{"state": "new"}, After: map[string]any{"state": "failed"}, CreatedAt: "2026-09-12T00:00:00Z",
	}}}
	responses := []any{auditBusinessResponse(result), auditGovernanceResponse(result), auditOperationsResponse(result)}
	for index, response := range responses {
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(encoded, &body); err != nil {
			t.Fatal(err)
		}
		item := body["items"].([]any)[0].(map[string]any)
		for key, want := range map[string]any{"actor_id": "user-1", "role_key": "manager", "request_id": "request-1", "result": "failed", "reason": "policy_denied"} {
			if item[key] != want {
				t.Fatalf("response %d %s=%v want=%v", index, key, item[key], want)
			}
		}
		if _, exposed := item["workspace_id"]; exposed {
			t.Fatalf("response %d exposes physical workspace_id", index)
		}
	}
}
