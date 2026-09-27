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
const exportMaxScanned = 10000

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
	if len(s.exportTokenKey) < 16 || authorizer == nil {
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
	rows := make([][]string, 0, exportMaxRows)
	access := map[[2]string]bool{}
	query := contract.AuditEventQuery{Event: filters.Event, ObjectKey: filters.ObjectKey, RecordID: filters.RecordID, ActorID: filters.ActorID, RoleKey: filters.RoleKey, CreatedFrom: filters.CreatedFrom, CreatedTo: filters.CreatedTo, Class: contract.AuditEventClassBusiness}
	scanned := 0
	for scanned < exportMaxScanned && len(rows) < exportMaxRows {
		query.Limit = 500
		if remaining := exportMaxScanned - scanned; remaining < query.Limit {
			query.Limit = remaining
		}
		events, err := s.reader.ListWithinDataScope(ctx, principal.WorkspaceID, query, scope)
		if err != nil {
			return contract.ExportPrepared{}, err
		}
		if len(events) == 0 {
			break
		}
		for _, event := range events {
			scanned++
			query.Cursor = contract.EncodeAuditEventCursor(event)
			if contract.ClassifyAuditEvent(event) != contract.AuditEventClassBusiness {
				continue
			}
			if event.RecordID != "" && authorizer != nil {
				key := [2]string{event.ObjectKey, event.RecordID}
				allowed, known := access[key]
				if !known {
					if event.ObjectKey != "" {
						allowed, err = sourceRecordVisible(authorizer(ctx, contract.ExportFilter{ObjectKey: event.ObjectKey, RecordID: event.RecordID}, principal))
						if err != nil {
							return contract.ExportPrepared{}, err
						}
					}
					access[key] = allowed
				}
				if !allowed {
					continue
				}
			}
			result := auditservice.ExportEventResult(event)
			if filters.Result != "" && !strings.EqualFold(filters.Result, result) {
				continue
			}
			rows = append(rows, []string{event.ID, event.Event, event.ObjectKey, event.RecordID, event.ActorID, event.RoleKey, auditservice.AuditEventRequestID(event), result, auditservice.ExportEventReason(event), event.CreatedAt})
			if len(rows) == exportMaxRows {
				break
			}
		}
		if len(events) < query.Limit {
			break
		}
	}
	if scanned == exportMaxScanned && len(rows) < exportMaxRows {
		return contract.ExportPrepared{}, exportError("export_scan_limit_exceeded", nil)
	}
	if len(rows) == 0 {
		return contract.ExportPrepared{}, exportError("export_no_results", nil)
	}
	content, err := encodeExportCSV(rows)
	if err != nil {
		return contract.ExportPrepared{}, exportError("export_encode_failed", err)
	}
	scopeHash := exportHash(filters)
	authorizationHash := exportAuthorizationHash(principal, scope)
	// Shared Artifact persists expiry in Unix milliseconds. The signed token
	// must use that same precision before the artifact is written and reread.
	expiresAt := now.Add(exportTTL).Truncate(time.Millisecond).Format(time.RFC3339Nano)
	artifactID := exportArtifactID(principal.WorkspaceID, principal.UserID, idempotencyKey)
	auditIdentity := "audit_events:" + artifactID + ":sha256:" + scopeHash
	token := s.exportToken(artifactID, scopeHash, expiresAt)
	artifact := contract.ExportArtifact{ID: artifactID, WorkspaceID: strings.TrimSpace(principal.WorkspaceID), RequesterUserID: strings.TrimSpace(principal.UserID), RoleKey: principal.RoleKey, IdempotencyKey: idempotencyKey, Filters: filters, ScopeSHA256: scopeHash, AuthorizationScopeSHA256: authorizationHash, TokenSHA256: exportHash(token), Filename: "audit-events-" + now.Format("20060102T150405Z") + ".csv", ContentSHA256: exportBytesHash(content), RowCount: len(rows), Content: content, AuditIdentity: auditIdentity, Status: "prepared", CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: expiresAt}
	stored, created, err := s.store.CreateOrGetExport(ctx, artifact)
	if errors.Is(err, contract.ErrExportIdempotencyConflict) {
		if auditErr := s.appendExportConflictAudit(ctx, principal, artifact.ID); auditErr != nil {
			return contract.ExportPrepared{}, auditErr
		}
		return contract.ExportPrepared{}, exportError("idempotency_key_conflict", err)
	}
	if err != nil {
		return contract.ExportPrepared{}, exportError("export_persistence_failed", err)
	}
	token = s.exportToken(stored.ID, stored.ScopeSHA256, stored.ExpiresAt)
	if exportHash(token) != stored.TokenSHA256 {
		return contract.ExportPrepared{}, exportError("export_integrity_failed", nil)
	}
	if err := s.appendExportAudit(ctx, "audit_export_prepared", principal, stored, map[string]any{"idempotency_replayed": !created, "result": "success", "reason": "export_prepared"}); err != nil {
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
	if len(s.exportTokenKey) < 16 || authorizer == nil {
		return nil, "", exportError("export_unavailable", nil)
	}
	token = strings.TrimSpace(token)
	if len(token) < 80 || len(token) > 160 {
		return nil, "", exportError("export_download_not_found", nil)
	}
	// The artifact belongs to its requester. The event scope controls which
	// rows can be exported; it is not an ownership scope for the artifact.
	artifactScope := auditrepository.OwnerDataScope(principal.UserID)
	a, found, err := s.store.ExportByTokenHashWithinDataScope(ctx, principal.WorkspaceID, exportHash(token), principal.UserID, artifactScope)
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
	now := s.clock.Now().UTC()
	if parseErr != nil || !now.Before(expiresAt) {
		return nil, "", exportError("export_download_expired", nil)
	}
	if exportAuthorizationHash(principal, scope) != a.AuthorizationScopeSHA256 {
		return nil, "", exportError("export_scope_changed", nil)
	}
	if authorizer != nil {
		if err := authorizer(ctx, a.Filters, principal); err != nil {
			return nil, "", err
		}
	}
	content, found, err := s.store.ExportContentWithinDataScope(ctx, a.WorkspaceID, a.ID, exportHash(token), principal.UserID, now, artifactScope)
	if err != nil {
		if errors.Is(err, auditrepository.ErrExportContentIntegrity) {
			return nil, "", exportError("export_integrity_failed", err)
		}
		return nil, "", exportError("export_persistence_failed", err)
	}
	if !found {
		return nil, "", exportError("export_download_not_found", nil)
	}
	if exportBytesHash(content) != a.ContentSHA256 || exportHash(a.Filters) != a.ScopeSHA256 {
		return nil, "", exportError("export_integrity_failed", nil)
	}
	if authorizer != nil {
		if err := reauthorizeExportRows(ctx, content, principal, authorizer); err != nil {
			return nil, "", err
		}
	}
	first, err := s.store.RecordExportDownloadWithinDataScope(ctx, a.WorkspaceID, a.ID, principal.UserID, now.Format(time.RFC3339Nano), artifactScope)
	if err != nil {
		return nil, "", exportError("export_persistence_failed", err)
	}
	if first {
		if err := s.appendExportAudit(ctx, "audit_export_downloaded", principal, a, map[string]any{"result": "success", "reason": "export_downloaded"}); err != nil {
			return nil, "", err
		}
	}
	return append([]byte(nil), content...), a.Filename, nil
}

func reauthorizeExportRows(ctx context.Context, content []byte, principal contract.ExportPrincipal, authorizer contract.ExportAuthorizer) error {
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(content, []byte{0xef, 0xbb, 0xbf})))
	reader.FieldsPerRecord = 10
	rows, err := reader.ReadAll()
	if err != nil || len(rows) == 0 || rows[0][0] != "audit_id" || rows[0][2] != "object_key" || rows[0][3] != "record_id" {
		return exportError("export_integrity_failed", err)
	}
	access := map[[2]string]bool{}
	for _, row := range rows[1:] {
		if row[3] == "" {
			continue
		}
		key := [2]string{row[2], row[3]}
		allowed, known := access[key]
		if !known {
			if row[2] != "" {
				allowed, err = sourceRecordVisible(authorizer(ctx, contract.ExportFilter{ObjectKey: row[2], RecordID: row[3]}, principal))
				if err != nil {
					return err
				}
			}
			access[key] = allowed
		}
		if !allowed {
			return exportError("export_scope_changed", nil)
		}
	}
	return nil
}

func encodeExportCSV(rows [][]string) ([]byte, error) {
	var b bytes.Buffer
	b.Write([]byte{0xef, 0xbb, 0xbf})
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"audit_id", "event", "object_key", "record_id", "actor_id", "role_key", "request_id", "result", "reason", "created_at"}); err != nil {
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
func exportAuthorizationHash(p contract.ExportPrincipal, scope auditrepository.DataScope) string {
	caps := append([]string(nil), p.SystemCapabilities...)
	sort.Strings(caps)
	scope = scope.Normalized()
	subjectIDs := append([]string(nil), scope.SubjectIDs...)
	organizationIDs := append([]string(nil), scope.OrganizationIDs...)
	sort.Strings(subjectIDs)
	sort.Strings(organizationIDs)
	return exportHash(struct {
		WorkspaceID           string   `json:"workspace_id"`
		UserID                string   `json:"user_id"`
		RoleKey               string   `json:"role_key"`
		AuthorizationRevision string   `json:"authorization_revision"`
		SystemScope           string   `json:"system_scope,omitempty"`
		SystemCapabilities    []string `json:"system_capabilities,omitempty"`
		ScopeAll              bool     `json:"scope_all"`
		ScopeSubjectIDs       []string `json:"scope_subject_ids,omitempty"`
		ScopeOrganizationIDs  []string `json:"scope_organization_ids,omitempty"`
	}{strings.TrimSpace(p.WorkspaceID), strings.TrimSpace(p.UserID), strings.TrimSpace(p.RoleKey), strings.TrimSpace(p.AuthorizationRevision), p.SystemScope, caps, scope.All, subjectIDs, organizationIDs})
}
func exportHash(v any) string         { encoded, _ := json.Marshal(v); return exportBytesHash(encoded) }
func exportBytesHash(v []byte) string { sum := sha256.Sum256(v); return hex.EncodeToString(sum[:]) }
func (s *ExportService) appendExportAudit(ctx context.Context, event string, p contract.ExportPrincipal, a contract.ExportArtifact, extra map[string]any) error {
	expiresAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(a.ExpiresAt))
	if err != nil {
		return exportError("export_audit_failed", err)
	}
	metadata := map[string]any{"artifact_id": a.ID, "audit_identity": a.AuditIdentity, "content_sha256": a.ContentSHA256, "scope_sha256": a.ScopeSHA256, "row_count": a.RowCount, "expires_at": expiresAt.UTC().UnixMilli()}
	if actorOrgID := exportActorOrgID(p); actorOrgID != "" {
		metadata["actor_org_id"] = actorOrgID
	}
	for k, v := range extra {
		metadata[k] = v
	}
	_, err = s.appender.Append(ctx, contract.AppendRequest{Family: contract.EventFamilyAuditExport, Event: event, ObjectKey: "audit_events", RecordID: a.ID, Actor: exportAuditActor(p), Summary: "Audit event export lifecycle", Metadata: metadata})
	if err != nil {
		return exportError("export_audit_failed", err)
	}
	return nil
}

func (s *ExportService) appendExportConflictAudit(ctx context.Context, p contract.ExportPrincipal, artifactID string) error {
	idempotencyKey := ""
	if requestID := strings.TrimSpace(p.RequestID); requestID != "" {
		idempotencyKey = "audit_export_conflict:" + requestID
	}
	_, err := s.appender.Append(ctx, contract.AppendRequest{
		IdempotencyKey: idempotencyKey,
		Family:         contract.EventFamilyAuditExport,
		Event:          "audit_export_conflict",
		ObjectKey:      "audit_events",
		RecordID:       artifactID,
		Actor:          exportAuditActor(p),
		Summary:        "Audit event export idempotency conflict",
		Metadata: map[string]any{
			"artifact_id": artifactID,
			"result":      "conflict",
			"reason":      "idempotency_fingerprint_conflict",
			"error_code":  "backend.idempotency.key_conflict",
		},
	})
	if err != nil {
		return exportError("export_audit_failed", err)
	}
	return nil
}

func exportAuditActor(p contract.ExportPrincipal) contract.Actor {
	return contract.Actor{
		WorkspaceID: p.WorkspaceID, SubjectID: p.UserID, RoleKey: p.RoleKey,
		RequestID: p.RequestID, CorrelationID: p.CorrelationID, AuthorizationRevision: p.AuthorizationRevision,
	}
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
