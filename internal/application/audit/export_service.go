package auditapp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	auditservice "github.com/domainry/domainry-audit/internal/domain/audit/service"
)

const exportTTL = 15 * time.Minute
const exportMaxRows = 1000

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type EventReader interface {
	ListWithinDataScope(context.Context, string, contract.Query, auditrepository.DataScope) ([]contract.Event, error)
}
type EventAppender interface {
	Append(context.Context, contract.AppendRequest) (contract.Event, error)
}

type ExportService struct {
	reader           EventReader
	store            auditrepository.ExportArtifactRepository
	appender         EventAppender
	clock            Clock
	exportTokenKey   []byte
	exportAuthorizer contract.ExportAuthorizer
}

func NewExportService(reader EventReader, store auditrepository.ExportArtifactRepository, appender EventAppender, clock Clock) *ExportService {
	if clock == nil {
		clock = systemClock{}
	}
	return &ExportService{reader: reader, store: store, appender: appender, clock: clock}
}

func (s *ExportService) ConfigureExport(key []byte, authorizer contract.ExportAuthorizer) {
	s.exportTokenKey = append([]byte(nil), key...)
	s.exportAuthorizer = authorizer
}

func (s *ExportService) PrepareExport(ctx context.Context, request contract.ExportRequest, idempotencyKey string, principal contract.ExportPrincipal) (contract.ExportPrepared, error) {
	return s.prepareExport(ctx, request, idempotencyKey, principal, auditrepository.OwnerDataScope(principal.UserID), s.exportAuthorizer)
}

func (s *ExportService) PrepareExportWithinDataScope(ctx context.Context, request contract.ExportRequest, idempotencyKey string, principal contract.ExportPrincipal, scope auditrepository.DataScope, authorizer contract.ExportAuthorizer) (contract.ExportPrepared, error) {
	return s.prepareExport(ctx, request, idempotencyKey, principal, scope.Normalized(), authorizer)
}

func (s *ExportService) prepareExport(ctx context.Context, request contract.ExportRequest, idempotencyKey string, principal contract.ExportPrincipal, scope auditrepository.DataScope, authorizer contract.ExportAuthorizer) (contract.ExportPrepared, error) {
	if len(s.exportTokenKey) < 16 {
		return contract.ExportPrepared{}, exportError("export_unavailable", nil)
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return contract.ExportPrepared{}, exportError("idempotency_key_required", nil)
	}
	now := s.clock.Now().UTC()
	filters, err := auditservice.NormalizeExportFilters(request, principal, now)
	if err != nil {
		return contract.ExportPrepared{}, err
	}
	if authorizer != nil {
		if err := authorizer(ctx, filters, principal); err != nil {
			return contract.ExportPrepared{}, err
		}
	}
	events, err := s.reader.ListWithinDataScope(ctx, principal.WorkspaceID, contract.AuditEventQuery{Event: filters.Event, ObjectKey: filters.ObjectKey, RecordID: filters.RecordID, ActorID: filters.ActorID, RoleKey: filters.RoleKey, CreatedFrom: filters.CreatedFrom, CreatedTo: filters.CreatedTo, Class: contract.AuditEventClassBusiness, Limit: exportMaxRows}, scope)
	if err != nil {
		return contract.ExportPrepared{}, err
	}
	rows := make([][]string, 0, len(events))
	for _, event := range events {
		if contract.ClassifyAuditEvent(event) != contract.AuditEventClassBusiness {
			continue
		}
		result := auditservice.ExportEventResult(event)
		if filters.Result != "" && !strings.EqualFold(filters.Result, result) {
			continue
		}
		rows = append(rows, []string{event.ID, event.Event, event.ObjectKey, event.RecordID, event.ActorID, result, event.CreatedAt})
	}
	if len(rows) == 0 {
		return contract.ExportPrepared{}, exportError("export_no_results", nil)
	}
	content, err := encodeExportCSV(rows)
	if err != nil {
		return contract.ExportPrepared{}, exportError("export_encode_failed", err)
	}
	scopeHash := exportHash(filters)
	authorizationHash := exportAuthorizationHash(principal)
	expiresAt := now.Add(exportTTL).Format(time.RFC3339Nano)
	artifactID := exportArtifactID(principal.WorkspaceID, principal.UserID, idempotencyKey)
	auditIdentity := "audit_events:" + artifactID + ":sha256:" + scopeHash
	token := s.exportToken(artifactID, scopeHash, expiresAt)
	artifact := contract.ExportArtifact{ID: artifactID, WorkspaceID: strings.TrimSpace(principal.WorkspaceID), RequesterUserID: strings.TrimSpace(principal.UserID), RoleKey: principal.RoleKey, IdempotencyKey: idempotencyKey, Filters: filters, ScopeSHA256: scopeHash, AuthorizationScopeSHA256: authorizationHash, TokenSHA256: exportHash(token), Filename: "audit-events-" + now.Format("20060102T150405Z") + ".csv", ContentSHA256: exportBytesHash(content), RowCount: len(rows), Content: content, AuditIdentity: auditIdentity, Status: "prepared", CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: expiresAt}
	stored, created, err := s.store.CreateOrGetExport(ctx, artifact)
	if errors.Is(err, contract.ErrExportIdempotencyConflict) {
		return contract.ExportPrepared{}, exportError("idempotency_key_conflict", err)
	}
	if err != nil {
		return contract.ExportPrepared{}, exportError("export_persistence_failed", err)
	}
	token = s.exportToken(stored.ID, stored.ScopeSHA256, stored.ExpiresAt)
	if exportHash(token) != stored.TokenSHA256 {
		return contract.ExportPrepared{}, exportError("export_integrity_failed", nil)
	}
	if err := s.appendExportAudit(ctx, "audit_export_prepared", principal, stored, map[string]any{"idempotency_replayed": !created}); err != nil {
		return contract.ExportPrepared{}, err
	}
	return preparedExport(stored, token), nil
}

func (s *ExportService) DownloadExport(ctx context.Context, token string, principal contract.ExportPrincipal) ([]byte, string, error) {
	return s.downloadExport(ctx, token, principal, auditrepository.OwnerDataScope(principal.UserID), s.exportAuthorizer)
}

func (s *ExportService) DownloadExportWithinDataScope(ctx context.Context, token string, principal contract.ExportPrincipal, scope auditrepository.DataScope, authorizer contract.ExportAuthorizer) ([]byte, string, error) {
	return s.downloadExport(ctx, token, principal, scope.Normalized(), authorizer)
}

func (s *ExportService) downloadExport(ctx context.Context, token string, principal contract.ExportPrincipal, scope auditrepository.DataScope, authorizer contract.ExportAuthorizer) ([]byte, string, error) {
	if len(s.exportTokenKey) < 16 {
		return nil, "", exportError("export_unavailable", nil)
	}
	token = strings.TrimSpace(token)
	if len(token) < 80 || len(token) > 160 {
		return nil, "", exportError("export_download_not_found", nil)
	}
	a, found, err := s.store.ExportByTokenHashWithinDataScope(ctx, principal.WorkspaceID, exportHash(token), principal.UserID, scope)
	if err != nil {
		return nil, "", exportError("export_persistence_failed", err)
	}
	if !found || !hmac.Equal([]byte(token), []byte(s.exportToken(a.ID, a.ScopeSHA256, a.ExpiresAt))) {
		return nil, "", exportError("export_download_not_found", nil)
	}
	if a.RequesterUserID != strings.TrimSpace(principal.UserID) || a.WorkspaceID != strings.TrimSpace(principal.WorkspaceID) {
		return nil, "", exportError("export_requester_mismatch", nil)
	}
	expiresAt, parseErr := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if parseErr != nil || !s.clock.Now().UTC().Before(expiresAt) {
		return nil, "", exportError("export_download_expired", nil)
	}
	if exportAuthorizationHash(principal) != a.AuthorizationScopeSHA256 {
		return nil, "", exportError("export_scope_changed", nil)
	}
	if authorizer != nil {
		if err := authorizer(ctx, a.Filters, principal); err != nil {
			return nil, "", err
		}
	}
	if exportBytesHash(a.Content) != a.ContentSHA256 || exportHash(a.Filters) != a.ScopeSHA256 {
		return nil, "", exportError("export_integrity_failed", nil)
	}
	first, err := s.store.RecordExportDownloadWithinDataScope(ctx, a.WorkspaceID, a.ID, principal.UserID, s.clock.Now().UTC().Format(time.RFC3339Nano), scope)
	if err != nil {
		return nil, "", exportError("export_persistence_failed", err)
	}
	if first {
		if err := s.appendExportAudit(ctx, "audit_export_downloaded", principal, a, nil); err != nil {
			return nil, "", err
		}
	}
	return append([]byte(nil), a.Content...), a.Filename, nil
}

func encodeExportCSV(rows [][]string) ([]byte, error) {
	var b bytes.Buffer
	b.Write([]byte{0xef, 0xbb, 0xbf})
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"audit_id", "event", "object_key", "record_id", "actor_id", "result", "created_at"}); err != nil {
		return nil, err
	}
	if err := w.WriteAll(rows); err != nil {
		return nil, err
	}
	w.Flush()
	return b.Bytes(), w.Error()
}
func (s *ExportService) exportToken(id, scope, expires string) string {
	payload := id + "." + expires
	mac := hmac.New(sha256.New, s.exportTokenKey)
	_, _ = mac.Write([]byte(payload + "\x00" + scope))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}
func exportArtifactID(w, u, k string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(w) + "\x00" + strings.TrimSpace(u) + "\x00audit_events\x00" + strings.TrimSpace(k)))
	return "audexp_" + hex.EncodeToString(sum[:16])
}
func exportAuthorizationHash(p contract.ExportPrincipal) string {
	caps := append([]string(nil), p.SystemCapabilities...)
	sort.Strings(caps)
	return exportHash(struct {
		WorkspaceID           string   `json:"workspace_id"`
		UserID                string   `json:"user_id"`
		RoleKey               string   `json:"role_key"`
		AuthorizationRevision string   `json:"authorization_revision"`
		SystemScope           string   `json:"system_scope,omitempty"`
		SystemCapabilities    []string `json:"system_capabilities,omitempty"`
	}{strings.TrimSpace(p.WorkspaceID), strings.TrimSpace(p.UserID), strings.TrimSpace(p.RoleKey), strings.TrimSpace(p.AuthorizationRevision), p.SystemScope, caps})
}
func exportHash(v any) string         { encoded, _ := json.Marshal(v); return exportBytesHash(encoded) }
func exportBytesHash(v []byte) string { sum := sha256.Sum256(v); return hex.EncodeToString(sum[:]) }
func (s *ExportService) appendExportAudit(ctx context.Context, event string, p contract.ExportPrincipal, a contract.ExportArtifact, extra map[string]any) error {
	metadata := map[string]any{"artifact_id": a.ID, "audit_identity": a.AuditIdentity, "content_sha256": a.ContentSHA256, "scope_sha256": a.ScopeSHA256, "row_count": a.RowCount, "expires_at": a.ExpiresAt}
	if actorOrgID := exportActorOrgID(p); actorOrgID != "" {
		metadata["actor_org_id"] = actorOrgID
	}
	for k, v := range extra {
		metadata[k] = v
	}
	_, err := s.appender.Append(ctx, contract.AppendRequest{Event: event, ObjectKey: "audit_events", RecordID: a.ID, Actor: contract.Actor{WorkspaceID: p.WorkspaceID, SubjectID: p.UserID, RoleKey: p.RoleKey, AuthorizationRevision: p.AuthorizationRevision}, Summary: "Audit event export lifecycle", Metadata: metadata})
	if err != nil {
		return exportError("export_audit_failed", err)
	}
	return nil
}

func exportActorOrgID(principal contract.ExportPrincipal) string {
	context, ok := principal.AuthorizationContext.(auditExportAuthorizationContext)
	if !ok {
		return ""
	}
	return strings.TrimSpace(context.Principal.Identity.OrgID)
}
func preparedExport(a contract.ExportArtifact, token string) contract.ExportPrepared {
	return contract.ExportPrepared{ID: a.ID, ReportSource: "audit_events", Filename: a.Filename, ContentSHA256: a.ContentSHA256, RowCount: a.RowCount, AuditIdentity: a.AuditIdentity, ScopeSHA256: a.ScopeSHA256, Filters: a.Filters, DownloadToken: token, ExpiresAt: a.ExpiresAt}
}
func exportError(code string, err error) error { return &contract.ExportError{Code: code, Err: err} }
