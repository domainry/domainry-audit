package policy

import (
	"testing"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
)

func TestNormalizeFiltersAppliesRetentionAndActorScope(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	filters, err := NormalizeFilters(contract.ExportRequest{}, contract.ExportPrincipal{UserID: "user", RoleKey: "member"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if filters.ActorID != "user" || filters.CreatedFrom != now.AddDate(0, 0, -retentionDays).Format(time.RFC3339) {
		t.Fatalf("filters=%+v", filters)
	}
}
