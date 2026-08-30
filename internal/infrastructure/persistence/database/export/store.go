package exportstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

type Store struct {
	db       modulehost.Database
	renderer ormbuilder.Renderer
}

func NewStore(db modulehost.Database, renderer ormbuilder.Renderer) *Store {
	return &Store{db: db, renderer: renderer}
}

func (s *Store) CreateOrGetExport(ctx context.Context, artifact contract.ExportArtifact) (contract.ExportArtifact, bool, error) {
	if err := validateExport(artifact); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if current, found, err := s.exportByIdempotency(ctx, artifact); err != nil {
		return contract.ExportArtifact{}, false, err
	} else if found {
		if !sameExportRequest(current, artifact) {
			return contract.ExportArtifact{}, false, contract.ErrExportIdempotencyConflict
		}
		return current, false, nil
	}
	artifact.ID = exportID(artifact)
	filters, _ := json.Marshal(artifact.Filters)
	statement, args, err := ormbuilder.NewWorkspaceInsertBuilder(s.renderer, "_audit_export_artifacts", artifact.WorkspaceID).
		Columns(exportWorkspaceColumns()...).Values(artifact.ID, artifact.RequesterUserID, artifact.RoleKey, artifact.IdempotencyKey, string(filters), artifact.ScopeSHA256, artifact.AuthorizationScopeSHA256, artifact.TokenSHA256, artifact.Filename, artifact.ContentSHA256, artifact.RowCount, base64.StdEncoding.EncodeToString(artifact.Content), artifact.AuditIdentity, artifact.Status, artifact.CreatedAt, artifact.ExpiresAt, artifact.DownloadCount, artifact.LastDownloadedAt).Build()
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if _, err = s.db.ExecContext(ctx, statement, args...); err != nil {
		if current, found, readErr := s.exportByIdempotency(ctx, artifact); readErr == nil && found {
			if sameExportRequest(current, artifact) {
				return current, false, nil
			}
			return contract.ExportArtifact{}, false, contract.ErrExportIdempotencyConflict
		}
		return contract.ExportArtifact{}, false, err
	}
	return artifact, true, nil
}

func (s *Store) ExportByTokenHash(ctx context.Context, workspaceID, tokenHash string) (contract.ExportArtifact, bool, error) {
	statement, args, err := s.exportSelect(workspaceID).Where(ormbuilder.Equal("token_sha256", strings.TrimSpace(tokenHash))).Limit(1).Build()
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	return scanExport(s.db.QueryRowContext(ctx, statement, args...))
}

func (s *Store) RecordExportDownload(ctx context.Context, workspaceID, artifactID, downloadedAt string) (bool, error) {
	statement, args, err := ormbuilder.NewWorkspaceUpdateBuilder(s.renderer, "_audit_export_artifacts", strings.TrimSpace(workspaceID)).Set("download_count", 1).Set("last_downloaded_at", strings.TrimSpace(downloadedAt)).Set("status", "downloaded").Where(ormbuilder.And(ormbuilder.Equal("id", strings.TrimSpace(artifactID)), ormbuilder.Equal("download_count", 0))).Build()
	if err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, statement, args...)
	if err != nil {
		return false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return true, nil
	}
	lookup, lookupArgs, err := ormbuilder.NewWorkspaceSelectBuilder(s.renderer, "_audit_export_artifacts", workspaceID).Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.Equal("id", strings.TrimSpace(artifactID))).Build()
	if err != nil {
		return false, err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, lookup, lookupArgs...).Scan(&count); err != nil {
		return false, err
	}
	if count != 1 {
		return false, fmt.Errorf("audit export artifact not found")
	}
	return false, nil
}

func (s *Store) exportByIdempotency(ctx context.Context, artifact contract.ExportArtifact) (contract.ExportArtifact, bool, error) {
	statement, args, err := s.exportSelect(artifact.WorkspaceID).Where(ormbuilder.And(ormbuilder.Equal("requester_user_id", artifact.RequesterUserID), ormbuilder.Equal("idempotency_key", artifact.IdempotencyKey))).Limit(1).Build()
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	return scanExport(s.db.QueryRowContext(ctx, statement, args...))
}
func (s *Store) exportSelect(workspaceID string) *ormbuilder.SelectBuilder {
	return ormbuilder.NewWorkspaceSelectBuilder(s.renderer, "_audit_export_artifacts", strings.TrimSpace(workspaceID)).Columns(exportColumns()...)
}
func exportColumns() []string {
	return []string{"id", "workspace_id", "requester_user_id", "role_key", "idempotency_key", "filters_json", "scope_sha256", "authorization_scope_sha256", "token_sha256", "filename", "content_sha256", "row_count", "content_base64", "audit_identity", "status", "created_at", "expires_at", "download_count", "last_downloaded_at"}
}
func exportWorkspaceColumns() []string {
	return []string{"id", "requester_user_id", "role_key", "idempotency_key", "filters_json", "scope_sha256", "authorization_scope_sha256", "token_sha256", "filename", "content_sha256", "row_count", "content_base64", "audit_identity", "status", "created_at", "expires_at", "download_count", "last_downloaded_at"}
}
func scanExport(row *sql.Row) (contract.ExportArtifact, bool, error) {
	var a contract.ExportArtifact
	var filters, content string
	err := row.Scan(&a.ID, &a.WorkspaceID, &a.RequesterUserID, &a.RoleKey, &a.IdempotencyKey, &filters, &a.ScopeSHA256, &a.AuthorizationScopeSHA256, &a.TokenSHA256, &a.Filename, &a.ContentSHA256, &a.RowCount, &content, &a.AuditIdentity, &a.Status, &a.CreatedAt, &a.ExpiresAt, &a.DownloadCount, &a.LastDownloadedAt)
	if err == sql.ErrNoRows {
		return contract.ExportArtifact{}, false, nil
	}
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if err := json.Unmarshal([]byte(filters), &a.Filters); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	a.Content, err = base64.StdEncoding.DecodeString(content)
	return a, true, err
}
func validateExport(a contract.ExportArtifact) error {
	if strings.TrimSpace(a.WorkspaceID) == "" || strings.TrimSpace(a.RequesterUserID) == "" || strings.TrimSpace(a.IdempotencyKey) == "" || strings.TrimSpace(a.ScopeSHA256) == "" || strings.TrimSpace(a.AuthorizationScopeSHA256) == "" || strings.TrimSpace(a.TokenSHA256) == "" || strings.TrimSpace(a.ContentSHA256) == "" || strings.TrimSpace(a.AuditIdentity) == "" || a.RowCount < 1 || len(a.Content) == 0 {
		return fmt.Errorf("complete audit export identity, scope, and content are required")
	}
	return nil
}
func sameExportRequest(a, b contract.ExportArtifact) bool {
	return a.ScopeSHA256 == b.ScopeSHA256 && a.AuthorizationScopeSHA256 == b.AuthorizationScopeSHA256
}
func exportID(a contract.ExportArtifact) string {
	sum := sha256.Sum256([]byte(a.WorkspaceID + "\x00" + a.RequesterUserID + "\x00audit_events\x00" + a.IdempotencyKey))
	return "audexp_" + hex.EncodeToString(sum[:16])
}
