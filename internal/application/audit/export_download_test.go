package auditapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	"github.com/domainry/domainry-foundation/apperror"
)

func TestDownloadExportOpensBlobOnlyAfterAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	principal := contract.ExportPrincipal{
		WorkspaceID: "workspace", UserID: "requester", RoleKey: "member", AuthorizationRevision: "revision-1",
	}

	t.Run("authorized", func(t *testing.T) {
		service, store, token := exportDownloadFixture(now, principal, now.Add(time.Minute), nil)
		content, filename, err := service.DownloadExport(t.Context(), token, principal)
		if err != nil || string(content) != exportFixtureCSV || filename != "audit.csv" {
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

	t.Run("missing source authorizer", func(t *testing.T) {
		service, store, token := exportDownloadFixture(now, principal, now.Add(time.Minute), nil)
		service.ConfigureExport([]byte("0123456789abcdef0123456789abcdef"), nil)
		if _, _, err := service.DownloadExport(t.Context(), token, principal); err == nil || store.contentReads != 0 {
			t.Fatalf("unguarded download err=%v reads=%d", err, store.contentReads)
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

	t.Run("organization event scope changed", func(t *testing.T) {
		original := auditrepository.DataScope{OrganizationIDs: []string{"team-a"}}
		service, store, token := exportDownloadFixture(now, principal, now.Add(time.Minute), nil, original)
		if _, _, err := service.DownloadExportWithinDataScope(t.Context(), token, principal, original, service.exportAuthorizer); err != nil {
			t.Fatalf("original organization scope could not download: %v", err)
		}
		store.contentReads = 0
		moved := auditrepository.DataScope{OrganizationIDs: []string{"team-b"}}
		if _, _, err := service.DownloadExportWithinDataScope(t.Context(), token, principal, moved, service.exportAuthorizer); err == nil {
			t.Fatal("changed organization event scope downloaded old content")
		}
		if store.contentReads != 0 {
			t.Fatalf("changed organization scope opened Blob %d times", store.contentReads)
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

	t.Run("source record access revoked", func(t *testing.T) {
		denied := false
		service, _, token := exportDownloadFixture(now, principal, now.Add(time.Minute), func(_ context.Context, filter contract.ExportFilter, _ contract.ExportPrincipal) error {
			if denied && filter.RecordID == "order-1" {
				return apperror.New(apperror.KindForbidden, "test.record_denied", nil, nil)
			}
			return nil
		})
		if _, _, err := service.DownloadExport(t.Context(), token, principal); err != nil {
			t.Fatal(err)
		}
		denied = true
		if _, _, err := service.DownloadExport(t.Context(), token, principal); err == nil {
			t.Fatal("download succeeded after source access changed")
		}
	})
}

const exportFixtureCSV = "audit_id,event,object_key,record_id,actor_id,role_key,request_id,result,reason,created_at\naudit-1,order.completed,order,order-1,requester,member,request-1,success,completed,2026-09-23T10:00:00Z\n"

func exportDownloadFixture(now time.Time, principal contract.ExportPrincipal, expiresAt time.Time, authorizer contract.ExportAuthorizer, scopes ...auditrepository.DataScope) (*ExportService, *exportDownloadStore, string) {
	if authorizer == nil {
		authorizer = func(context.Context, contract.ExportFilter, contract.ExportPrincipal) error { return nil }
	}
	store := &exportDownloadStore{content: []byte(exportFixtureCSV)}
	service := NewExportService(nil, store, nil, exportDownloadClock{now: now})
	service.ConfigureExport([]byte("0123456789abcdef0123456789abcdef"), authorizer)
	scope := auditrepository.OwnerDataScope(principal.UserID)
	if len(scopes) != 0 {
		scope = scopes[0]
	}
	store.artifact = contract.ExportArtifact{
		ID: "audexp_download", WorkspaceID: principal.WorkspaceID, RequesterUserID: principal.UserID,
		RoleKey: principal.RoleKey, Filters: contract.ExportFilter{Event: "order.completed"},
		ScopeSHA256:              exportHash(contract.ExportFilter{Event: "order.completed"}),
		AuthorizationScopeSHA256: exportAuthorizationHash(principal, scope), Filename: "audit.csv",
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
