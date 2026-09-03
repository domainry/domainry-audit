package exportstore

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	auditpersistence "github.com/domainry/domainry-audit/internal/infrastructure/persistence"
	ormdialect "github.com/domainry/domainry-orm/dialect"
	ormmigration "github.com/domainry/domainry-orm/migration"
	_ "modernc.org/sqlite"
)

type exportCaptureDatabase struct {
	*sql.DB
	lastQuery string
}

func (database *exportCaptureDatabase) QueryRowContext(ctx context.Context, statement string, args ...any) *sql.Row {
	database.lastQuery = statement
	return database.DB.QueryRowContext(ctx, statement, args...)
}

func TestExportArtifactReadsAndWritesStayWithinRequesterScope(t *testing.T) {
	database, renderer := openExportStoreTestDatabase(t)
	capture := &exportCaptureDatabase{DB: database}
	store := NewStore(capture, renderer)
	artifact, created, err := store.CreateOrGetExport(t.Context(), exportStoreTestArtifact())
	if err != nil || !created {
		t.Fatalf("create artifact=%#v created=%v err=%v", artifact, created, err)
	}

	if _, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "other", auditrepository.OwnerDataScope("other")); err != nil || found {
		t.Fatalf("another requester read artifact: found=%v err=%v", found, err)
	}
	if _, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "requester", auditrepository.DataScope{OrganizationIDs: []string{"org-a"}}); err != nil || found {
		t.Fatalf("organization-only scope inferred artifact ownership: found=%v err=%v", found, err)
	}
	if current, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "requester", auditrepository.OwnerDataScope("requester")); err != nil || !found || current.ID != artifact.ID {
		t.Fatalf("requester artifact=%#v found=%v err=%v", current, found, err)
	}

	if first, err := store.RecordExportDownloadWithinDataScope(t.Context(), "workspace", artifact.ID, "other", "2026-09-03T00:01:00Z", auditrepository.OwnerDataScope("other")); err == nil || first {
		t.Fatalf("another requester updated artifact: first=%v err=%v", first, err)
	}
	var downloads int
	if err := database.QueryRowContext(t.Context(), `SELECT download_count FROM _audit_export_artifacts WHERE workspace_id = 'workspace' AND id = ?`, artifact.ID).Scan(&downloads); err != nil || downloads != 0 {
		t.Fatalf("denied update changed artifact: downloads=%d err=%v", downloads, err)
	}
	if first, err := store.RecordExportDownloadWithinDataScope(t.Context(), "workspace", artifact.ID, "requester", "2026-09-03T00:01:00Z", auditrepository.OwnerDataScope("requester")); err != nil || !first {
		t.Fatalf("requester update first=%v err=%v", first, err)
	}
	if err := database.QueryRowContext(t.Context(), `SELECT download_count FROM _audit_export_artifacts WHERE workspace_id = 'workspace' AND id = ?`, artifact.ID).Scan(&downloads); err != nil || downloads != 1 {
		t.Fatalf("requester update count=%d err=%v", downloads, err)
	}

	if _, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "requester", auditrepository.AllDataScope()); err != nil || !found {
		t.Fatalf("all artifact lookup found=%v err=%v", found, err)
	}
	_, where, _ := strings.Cut(capture.lastQuery, " WHERE ")
	if !strings.Contains(where, "requester_user_id") || strings.Contains(where, " IN ") || strings.Contains(where, "1 = 0") {
		t.Fatalf("all did not preserve the requester invariant without a data-range predicate: %s", capture.lastQuery)
	}
}

func openExportStoreTestDatabase(t *testing.T) (*sql.DB, ormdialect.Renderer) {
	t.Helper()
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	renderer, err := ormdialect.ParseRenderer("sqlite", "", "")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := auditpersistence.SchemaMigrations(renderer, "sqlite")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := ormmigration.NewRunner(database, renderer, ormmigration.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Apply(t.Context(), migrations); err != nil {
		t.Fatal(err)
	}
	return database, renderer
}

func exportStoreTestArtifact() contract.ExportArtifact {
	return contract.ExportArtifact{
		WorkspaceID: "workspace", RequesterUserID: "requester", RoleKey: "member", IdempotencyKey: "idempotency",
		ScopeSHA256: "scope", AuthorizationScopeSHA256: "authorization", TokenSHA256: "token", Filename: "audit.csv",
		ContentSHA256: "content", RowCount: 1, Content: []byte("content"), AuditIdentity: "audit", Status: "prepared",
		CreatedAt: "2026-09-03T00:00:00Z", ExpiresAt: "2026-09-03T00:15:00Z",
	}
}
