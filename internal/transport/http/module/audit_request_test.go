package module

import (
	"net/http/httptest"
	"testing"
)

func TestAuditEventQueryParsesExplicitCorrelationIdentities(t *testing.T) {
	request := httptest.NewRequest("GET", "/audit/events?operation_id=operation-1&causation_id=cause-1&owner_run_id=workflow-1", nil)
	query := auditEventQuery(request)
	if query.OperationID != "operation-1" || query.CausationID != "cause-1" || query.OwnerRunID != "workflow-1" {
		t.Fatalf("query=%#v", query)
	}
}
