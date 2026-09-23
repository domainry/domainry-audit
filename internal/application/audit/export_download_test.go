package auditapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
)

func TestDownloadExportOpensBlobOnlyAfterAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	principal := contract.ExportPrincipal{
		WorkspaceID: "workspace", UserID: "requester", RoleKey: "member", AuthorizationRevision: "revision-1",
	}

	t.Run("authorized", func(t *testing.T) {
		service, store, token := exportDownloadFixture(now, principal, now.Add(time.Minute), nil)
		content, filename, err := service.DownloadExport(t.Context(), token, principal)
		if err != nil || string(content) != "content" || filename != "audit.csv" {
			t.Fatalf("content=%q filename=%q err=%v", content, filename, err)
		}
		if store.contentReads != 1 {
			t.Fatalf("authorized download content reads=%d", store.contentReads)
		}
	})

	t.Run("expired", func(t *testing.T) {
		service, store, token := exportDownloadFixture(now, principal, now, nil)
		if _, _, err := service.DownloadExport(t.Context(), token, principal); err == nil {
			t.Fatal("expired download succeeded")
		}
		if store.contentReads != 0 {
			t.Fatalf("expired download opened Blob %d times", store.contentReads)
		}
	})

	t.Run("authorization scope changed", func(t *testing.T) {
		service, store, token := exportDownloadFixture(now, principal, now.Add(time.Minute), nil)
		changed := principal
		changed.AuthorizationRevision = "revision-2"
		if _, _, err := service.DownloadExport(t.Context(), token, changed); err == nil {
			t.Fatal("changed authorization scope downloaded content")
		}
		if store.contentReads != 0 {
			t.Fatalf("changed authorization scope opened Blob %d times", store.contentReads)
		}
	})

	t.Run("current authorizer denied", func(t *testing.T) {
		denied := errors.New("denied")
		service, store, token := exportDownloadFixture(now, principal, now.Add(time.Minute), func(context.Context, contract.ExportFilter, contract.ExportPrincipal) error {
			return denied
		})
		if _, _, err := service.DownloadExport(t.Context(), token, principal); !errors.Is(err, denied) {
			t.Fatalf("denied download err=%v", err)
		}
		if store.contentReads != 0 {
			t.Fatalf("denied current authorization opened Blob %d times", store.contentReads)
		}
	})
}

func exportDownloadFixture(now time.Time, principal contract.ExportPrincipal, expiresAt time.Time, authorizer contract.ExportAuthorizer) (*ExportService, *exportDownloadStore, string) {
	store := &exportDownloadStore{content: []byte("content")}
	service := NewExportService(nil, store, nil, exportDownloadClock{now: now})
	service.ConfigureExport([]byte("0123456789abcdef0123456789abcdef"), authorizer)
	store.artifact = contract.ExportArtifact{
		ID: "audexp_download", WorkspaceID: principal.WorkspaceID, RequesterUserID: principal.UserID,
		RoleKey: principal.RoleKey, Filters: contract.ExportFilter{Event: "order.completed"},
		ScopeSHA256:              exportHash(contract.ExportFilter{Event: "order.completed"}),
		AuthorizationScopeSHA256: exportAuthorizationHash(principal), Filename: "audit.csv",
		ContentSHA256: exportBytesHash(store.content), Status: "prepared",
		CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: expiresAt.Format(time.RFC3339Nano),
	}
	token := service.exportToken(store.artifact.ID, store.artifact.ScopeSHA256, store.artifact.ExpiresAt)
	store.artifact.TokenSHA256 = exportHash(token)
	return service, store, token
}

type exportDownloadClock struct{ now time.Time }

func (c exportDownloadClock) Now() time.Time { return c.now }

type exportDownloadStore struct {
	artifact     contract.ExportArtifact
	content      []byte
	contentReads int
}

func (s *exportDownloadStore) CreateOrGetExport(context.Context, contract.ExportArtifact) (contract.ExportArtifact, bool, error) {
	return contract.ExportArtifact{}, false, errors.New("unexpected export creation")
}

func (s *exportDownloadStore) ExportByTokenHash(_ context.Context, workspaceID, tokenHash string) (contract.ExportArtifact, bool, error) {
	if workspaceID != s.artifact.WorkspaceID || tokenHash != s.artifact.TokenSHA256 {
		return contract.ExportArtifact{}, false, nil
	}
	return s.artifact, true, nil
}

func (s *exportDownloadStore) ExportByTokenHashWithinDataScope(_ context.Context, workspaceID, tokenHash, requesterUserID string, _ auditrepository.DataScope) (contract.ExportArtifact, bool, error) {
	if workspaceID != s.artifact.WorkspaceID || tokenHash != s.artifact.TokenSHA256 || requesterUserID != s.artifact.RequesterUserID {
		return contract.ExportArtifact{}, false, nil
	}
	return s.artifact, true, nil
}

func (s *exportDownloadStore) ExportContentWithinDataScope(_ context.Context, workspaceID, artifactID, tokenHash, requesterUserID string, authorizedAt time.Time, _ auditrepository.DataScope) ([]byte, bool, error) {
	s.contentReads++
	if workspaceID != s.artifact.WorkspaceID || artifactID != s.artifact.ID || tokenHash != s.artifact.TokenSHA256 || requesterUserID != s.artifact.RequesterUserID || !authorizedAt.Before(timeMustParse(s.artifact.ExpiresAt)) {
		return nil, false, nil
	}
	return append([]byte(nil), s.content...), true, nil
}

func (s *exportDownloadStore) RecordExportDownload(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *exportDownloadStore) RecordExportDownloadWithinDataScope(context.Context, string, string, string, string, auditrepository.DataScope) (bool, error) {
	return false, nil
}

func timeMustParse(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(err)
	}
	return parsed
}
