package auditapp

import (
	"context"
	"testing"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
)

type exportAuditCapture struct{ request contract.AppendRequest }

func (capture *exportAuditCapture) Append(_ context.Context, request contract.AppendRequest) (contract.Event, error) {
	capture.request = request
	return contract.Event{}, nil
}

func TestExportAuditMetadataOwnsNumericExpiry(t *testing.T) {
	capture := &exportAuditCapture{}
	service := NewExportService(nil, nil, capture, nil)
	expires := time.Date(2026, 9, 25, 18, 0, 0, 123_000_000, time.FixedZone("local", 8*3600))
	artifact := contract.ExportArtifact{ID: "export", ExpiresAt: expires.Format(time.RFC3339Nano)}
	if err := service.appendExportAudit(t.Context(), "audit_export_prepared", contract.ExportPrincipal{WorkspaceID: "workspace", UserID: "user"}, artifact, nil); err != nil {
		t.Fatal(err)
	}
	if got := capture.request.Metadata["expires_at"]; got != expires.UnixMilli() {
		t.Fatalf("audit metadata expiry=%v want=%d", got, expires.UnixMilli())
	}
	if err := service.appendExportAudit(t.Context(), "audit_export_prepared", contract.ExportPrincipal{}, contract.ExportArtifact{ExpiresAt: "invalid"}, nil); err == nil {
		t.Fatal("accepted invalid export expiry")
	}
}
