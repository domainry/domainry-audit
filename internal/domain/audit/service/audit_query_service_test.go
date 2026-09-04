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
		{ID: "newer", Event: "order.updated", ActorID: "actor-1", Before: map[string]any{"password": "secret"}, CreatedAt: now.Format(time.RFC3339)},
		{ID: "older", Event: "order.created", ActorID: "actor-1", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339)},
	}, plan)
	if !result.Truncated || result.NextCursor == "" || len(result.Items) != 1 || result.Items[0].Before["password"] != "[REDACTED]" {
		t.Fatalf("business result=%#v", result)
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
