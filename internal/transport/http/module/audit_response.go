package module

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	"github.com/domainry/domainry-foundation/apperror"
)

type auditBusinessEventResponse struct {
	ID        string         `json:"id"`
	Event     string         `json:"event"`
	ObjectKey string         `json:"object_key,omitempty"`
	RecordID  string         `json:"record_id,omitempty"`
	ActorID   string         `json:"actor_id"`
	Summary   string         `json:"summary"`
	Before    map[string]any `json:"before,omitempty"`
	After     map[string]any `json:"after,omitempty"`
	CreatedAt string         `json:"created_at"`
}

type auditGovernanceEventResponse struct {
	ID        string         `json:"id"`
	Event     string         `json:"event"`
	ObjectKey string         `json:"object_key,omitempty"`
	RecordID  string         `json:"record_id,omitempty"`
	ActorID   string         `json:"actor_id"`
	RoleKey   string         `json:"role_key,omitempty"`
	Summary   string         `json:"summary"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Before    map[string]any `json:"before,omitempty"`
	After     map[string]any `json:"after,omitempty"`
	CreatedAt string         `json:"created_at"`
}

type auditOperationsEventResponse struct {
	ID        string         `json:"id"`
	Event     string         `json:"event"`
	ObjectKey string         `json:"object_key,omitempty"`
	RecordID  string         `json:"record_id,omitempty"`
	ActorID   string         `json:"actor_id"`
	Summary   string         `json:"summary"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt string         `json:"created_at"`
}

type auditPageResponse[T any] struct {
	Items          []T    `json:"items"`
	Count          int    `json:"count"`
	PageSize       int    `json:"page_size"`
	Truncated      bool   `json:"truncated"`
	NextCursor     string `json:"next_cursor,omitempty"`
	RetentionClass string `json:"retention_class"`
	RetentionDays  int    `json:"retention_days"`
}

func auditBusinessResponse(result auditapp.AuditSurfaceResult) auditPageResponse[auditBusinessEventResponse] {
	items := make([]auditBusinessEventResponse, 0, len(result.Items))
	for _, event := range result.Items {
		items = append(items, auditBusinessEventResponse{ID: event.ID, Event: event.Event, ObjectKey: event.ObjectKey, RecordID: event.RecordID, ActorID: event.ActorID, Summary: event.Summary, Before: event.Before, After: event.After, CreatedAt: event.CreatedAt})
	}
	return auditPage(result, items)
}

func auditGovernanceResponse(result auditapp.AuditSurfaceResult) auditPageResponse[auditGovernanceEventResponse] {
	items := make([]auditGovernanceEventResponse, 0, len(result.Items))
	for _, event := range result.Items {
		items = append(items, auditGovernanceEventResponse{ID: event.ID, Event: event.Event, ObjectKey: event.ObjectKey, RecordID: event.RecordID, ActorID: event.ActorID, RoleKey: event.RoleKey, Summary: event.Summary, Metadata: event.Metadata, Before: event.Before, After: event.After, CreatedAt: event.CreatedAt})
	}
	return auditPage(result, items)
}

func auditOperationsResponse(result auditapp.AuditSurfaceResult) auditPageResponse[auditOperationsEventResponse] {
	items := make([]auditOperationsEventResponse, 0, len(result.Items))
	for _, event := range result.Items {
		items = append(items, auditOperationsEventResponse{ID: event.ID, Event: event.Event, ObjectKey: event.ObjectKey, RecordID: event.RecordID, ActorID: event.ActorID, Summary: event.Summary, Metadata: event.Metadata, CreatedAt: event.CreatedAt})
	}
	return auditPage(result, items)
}

func auditPage[T any](result auditapp.AuditSurfaceResult, items []T) auditPageResponse[T] {
	return auditPageResponse[T]{Items: items, Count: len(items), PageSize: result.PageSize, Truncated: result.Truncated, NextCursor: result.NextCursor, RetentionClass: result.RetentionClass, RetentionDays: result.RetentionDays}
}

func writeAuditJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAuditError(w http.ResponseWriter, err error) {
	status, code := auditHTTPStatusAndCode(err)
	w.Header().Set("Cache-Control", "no-store")
	params := apperror.SanitizeParams(apperror.ParamsOf(err))
	writeAuditJSON(w, status, map[string]any{
		"error": code, "code": code, "message": code, "message_key": code, "params": params,
	})
}

func auditHTTPStatusAndCode(err error) (int, string) {
	if code := apperror.CodeOf(err); code == "backend.auth.token_required" {
		return http.StatusUnauthorized, code
	}
	var exported *contract.ExportError
	if errors.As(err, &exported) {
		code := "backend.audit." + strings.TrimSpace(exported.Code)
		switch exported.Code {
		case "export_unavailable", "export_encode_failed", "export_persistence_failed", "export_audit_failed":
			return http.StatusInternalServerError, code
		case "idempotency_key_conflict":
			return http.StatusConflict, "backend.idempotency.key_conflict"
		case "idempotency_key_required":
			return http.StatusBadRequest, "backend.idempotency.key_required"
		case "export_download_not_found":
			return http.StatusNotFound, code
		case "export_requester_mismatch", "export_download_expired", "export_scope_changed", "export_integrity_failed", "export_actor_scope_denied", "export_role_scope_denied":
			return http.StatusForbidden, code
		default:
			return http.StatusBadRequest, code
		}
	}
	switch apperror.KindOf(err) {
	case apperror.KindBadRequest:
		return http.StatusBadRequest, apperror.CodeOf(err)
	case apperror.KindForbidden:
		return http.StatusForbidden, apperror.CodeOf(err)
	case apperror.KindNotFound:
		return http.StatusNotFound, apperror.CodeOf(err)
	case apperror.KindConflict:
		return http.StatusConflict, apperror.CodeOf(err)
	case apperror.KindRateLimited:
		return http.StatusTooManyRequests, apperror.CodeOf(err)
	case apperror.KindUnavailable:
		return http.StatusServiceUnavailable, apperror.CodeOf(err)
	default:
		return http.StatusInternalServerError, apperror.CodeOf(err)
	}
}

func auditHTTPError(status int, code string, err error) error {
	kind := apperror.KindInternal
	switch status {
	case http.StatusBadRequest:
		kind = apperror.KindBadRequest
	case http.StatusUnauthorized, http.StatusForbidden:
		kind = apperror.KindForbidden
	case http.StatusNotFound:
		kind = apperror.KindNotFound
	case http.StatusConflict:
		kind = apperror.KindConflict
	}
	return apperror.New(kind, code, err, nil)
}

func auditDownloadDisposition(filename string) string {
	filename = strings.NewReplacer("/", "_", "\\", "_", "\r", "_", "\n", "_").Replace(strings.TrimSpace(filename))
	if filename == "" || filename == "." || filename == ".." {
		filename = "audit-events.csv"
	}
	if value := mime.FormatMediaType("attachment", map[string]string{"filename": filename}); value != "" {
		return value
	}
	return `attachment; filename="audit-events.csv"`
}
