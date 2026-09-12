package service

import (
	"testing"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
)

func TestBusinessQueryOwnsPaginationRetentionAndRedaction(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	plan, err := PlanQuery(EventClassBusiness, contract.Query{Limit: 1}, "actor-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Query.ActorID != "" || plan.Query.Limit != 2 || plan.PageSize != 1 || plan.RetentionDays != BusinessRetentionDays || plan.Query.Class != "business" {
		t.Fatalf("business plan=%#v", plan)
	}
	result := ProjectQuery([]contract.Event{
		{ID: "newer", Event: "order.updated", ActorID: "actor-1", RoleKey: "manager", Metadata: map[string]any{"request_id": "req-1", "decision": "approved", "reason": "policy_match", "token": "secret"}, Before: map[string]any{"password": "secret"}, CreatedAt: now.Format(time.RFC3339)},
		{ID: "older", Event: "order.created", ActorID: "actor-1", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339)},
	}, plan)
	if !result.Truncated || result.NextCursor == "" || len(result.Items) != 1 || result.Items[0].Before["password"] != "[REDACTED]" {
		t.Fatalf("business result=%#v", result)
	}
	item := result.Items[0]
	if item.RoleKey != "manager" || item.RequestID != "req-1" || item.Result != "approved" || item.Reason != "policy_match" || item.Metadata["token"] != "[REDACTED]" {
		t.Fatalf("business projection=%#v", item)
	}
}

func TestEveryAuditClassProjectsTheSameTraceFieldsAndRedactedMaps(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	for _, kind := range []EventClass{EventClassBusiness, EventClassGovernance, EventClassOperations} {
		plan, err := PlanQuery(kind, contract.Query{Limit: 10}, "actor-1", now)
		if err != nil {
			t.Fatal(err)
		}
		eventName := "order.failed"
		if kind == EventClassGovernance {
			eventName = "identity_role_failed"
		}
		if kind == EventClassOperations {
			eventName = "auth_login_failed"
		}
		result := ProjectQuery([]contract.Event{{
			ID: "event-1", Event: eventName, ActorID: "actor-1", RoleKey: "member", CreatedAt: now.Format(time.RFC3339),
			Metadata: map[string]any{"request_id": "request-1", "error_code": "denied_by_policy", "secret": "hidden"},
			Before:   map[string]any{"password": "before-secret"}, After: map[string]any{"token": "after-secret"},
		}}, plan)
		if len(result.Items) != 1 {
			t.Fatalf("%s items=%#v", kind, result.Items)
		}
		item := result.Items[0]
		if item.RequestID != "request-1" || item.RoleKey != "member" || item.Result != "failed" || item.Reason != "denied_by_policy" {
			t.Fatalf("%s trace fields=%#v", kind, item)
		}
		if item.Metadata["secret"] != "[REDACTED]" || item.Before["password"] != "[REDACTED]" || item.After["token"] != "[REDACTED]" {
			t.Fatalf("%s redaction=%#v", kind, item)
		}
	}
}

func TestQueryPlanRejectsInvalidCursorAndUnknownClass(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	if _, err := PlanQuery(EventClassBusiness, contract.Query{Cursor: "invalid"}, "actor", now); err == nil {
		t.Fatal("invalid Audit cursor was accepted")
	}
	if _, err := PlanQuery(EventClass("unknown"), contract.Query{}, "actor", now); err == nil {
		t.Fatal("unknown Audit event class was accepted")
	}
}
