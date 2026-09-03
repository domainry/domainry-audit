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
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	"github.com/domainry/domainry-orm/query"
)

type Store struct {
	db       modulehost.Database
	renderer query.Renderer
}

func NewStore(db modulehost.Database, renderer query.Renderer) *Store {
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
	statement, args, err := query.NewWorkspaceInsertBuilder(s.renderer, "_audit_export_artifacts", artifact.WorkspaceID).
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
	return s.exportByTokenHashWithinDataScope(ctx, workspaceID, tokenHash, "", auditrepository.AllDataScope())
}

func (s *Store) ExportByTokenHashWithinDataScope(ctx context.Context, workspaceID, tokenHash, requesterUserID string, scope auditrepository.DataScope) (contract.ExportArtifact, bool, error) {
	return s.exportByTokenHashWithinDataScope(ctx, workspaceID, tokenHash, requesterUserID, scope)
}

func (s *Store) exportByTokenHashWithinDataScope(ctx context.Context, workspaceID, tokenHash, requesterUserID string, scope auditrepository.DataScope) (contract.ExportArtifact, bool, error) {
	predicates := []query.Predicate{query.Equal("token_sha256", strings.TrimSpace(tokenHash))}
	if requesterUserID = strings.TrimSpace(requesterUserID); requesterUserID != "" {
		predicates = append(predicates, query.Equal("requester_user_id", requesterUserID))
	}
	if scopePredicate := exportArtifactDataScopePredicate(scope); scopePredicate != nil {
		predicates = append(predicates, scopePredicate)
	}
	statement, args, err := s.exportSelect(workspaceID).Where(query.And(predicates...)).Limit(1).Build()
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	return scanExport(s.db.QueryRowContext(ctx, statement, args...))
}

func (s *Store) RecordExportDownload(ctx context.Context, workspaceID, artifactID, downloadedAt string) (bool, error) {
	return s.recordExportDownloadWithinDataScope(ctx, workspaceID, artifactID, "", downloadedAt, auditrepository.AllDataScope())
}

func (s *Store) RecordExportDownloadWithinDataScope(ctx context.Context, workspaceID, artifactID, requesterUserID, downloadedAt string, scope auditrepository.DataScope) (bool, error) {
	return s.recordExportDownloadWithinDataScope(ctx, workspaceID, artifactID, requesterUserID, downloadedAt, scope)
}

func (s *Store) recordExportDownloadWithinDataScope(ctx context.Context, workspaceID, artifactID, requesterUserID, downloadedAt string, scope auditrepository.DataScope) (first bool, err error) {
	workspaceID, artifactID = strings.TrimSpace(workspaceID), strings.TrimSpace(artifactID)
	if workspaceID == "" || artifactID == "" {
		return false, fmt.Errorf("audit export artifact identity is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	predicates := []query.Predicate{query.Equal("id", artifactID)}
	if requesterUserID = strings.TrimSpace(requesterUserID); requesterUserID != "" {
		predicates = append(predicates, query.Equal("requester_user_id", requesterUserID))
	}
	if scopePredicate := exportArtifactDataScopePredicate(scope); scopePredicate != nil {
		predicates = append(predicates, scopePredicate)
	}
	lookup, lookupArgs, err := query.NewWorkspaceSelectBuilder(s.renderer, "_audit_export_artifacts", workspaceID).
		Columns("download_count").Where(query.And(predicates...)).Limit(1).Build()
	if err != nil {
		return false, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, lookup, lookupArgs...).Scan(&count); err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("audit export artifact not found")
		}
		return false, err
	}
	if count != 0 {
		if err = tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	updatePredicates := append([]query.Predicate(nil), predicates...)
	updatePredicates = append(updatePredicates, query.Equal("download_count", 0))
	statement, args, err := query.NewWorkspaceUpdateBuilder(s.renderer, "_audit_export_artifacts", workspaceID).
		Set("download_count", 1).Set("last_downloaded_at", strings.TrimSpace(downloadedAt)).Set("status", "downloaded").
		Where(query.And(updatePredicates...)).Build()
	if err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if changed != 1 {
		return false, fmt.Errorf("audit export artifact changed during scoped update")
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) exportByIdempotency(ctx context.Context, artifact contract.ExportArtifact) (contract.ExportArtifact, bool, error) {
	statement, args, err := s.exportSelect(artifact.WorkspaceID).Where(query.And(query.Equal("requester_user_id", artifact.RequesterUserID), query.Equal("idempotency_key", artifact.IdempotencyKey))).Limit(1).Build()
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	return scanExport(s.db.QueryRowContext(ctx, statement, args...))
}
func (s *Store) exportSelect(workspaceID string) *query.SelectBuilder {
	return query.NewWorkspaceSelectBuilder(s.renderer, "_audit_export_artifacts", strings.TrimSpace(workspaceID)).Columns(exportColumns()...)
}

// Export artifacts intentionally have no organization field: they are owned
// by their requester. Organization-only scopes therefore compile to false
// instead of inferring ownership from unrelated mutable directory data.
func exportArtifactDataScopePredicate(scope auditrepository.DataScope) query.Predicate {
	scope = scope.Normalized()
	if scope.All {
		return nil
	}
	values := make([]any, len(scope.SubjectIDs))
	for index := range scope.SubjectIDs {
		values[index] = scope.SubjectIDs[index]
	}
	if len(values) == 0 {
		return query.AlwaysFalse()
	}
	return query.In("requester_user_id", values...)
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
