package module

import (
	"net/http"
	"strings"
)

func (h *AuditHandler) listBusinessEvents(w http.ResponseWriter, r *http.Request) {
	principal, err := h.auditPrincipal(r)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	result, err := h.application.BusinessEvents(r.Context(), auditEventQuery(r), principal)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	writeAuditJSON(w, http.StatusOK, auditBusinessResponse(result))
}

func (h *AuditHandler) listGovernanceEvents(w http.ResponseWriter, r *http.Request) {
	principal, err := h.auditPrincipal(r)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	result, err := h.application.GovernanceEvents(r.Context(), auditEventQuery(r), principal)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	writeAuditJSON(w, http.StatusOK, auditGovernanceResponse(result))
}

func (h *AuditHandler) exportGovernanceEvents(w http.ResponseWriter, r *http.Request) {
	principal, err := h.auditPrincipal(r)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	result, err := h.application.ExportGovernanceEvents(r.Context(), auditEventQuery(r), principal)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="tenant-governance-audit.json"`)
	writeAuditJSON(w, http.StatusOK, auditGovernanceResponse(result))
}

func (h *AuditHandler) listOperationsEvents(w http.ResponseWriter, r *http.Request) {
	principal, err := h.auditPrincipal(r)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	result, err := h.application.OperationsEvents(r.Context(), auditEventQuery(r), principal)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	writeAuditJSON(w, http.StatusOK, auditOperationsResponse(result))
}

func (h *AuditHandler) exportOperationsEvents(w http.ResponseWriter, r *http.Request) {
	principal, err := h.auditPrincipal(r)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	result, err := h.application.ExportOperationsEvents(r.Context(), auditEventQuery(r), principal)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="runtime-operations-audit.json"`)
	writeAuditJSON(w, http.StatusOK, auditOperationsResponse(result))
}

func (h *AuditHandler) prepareBusinessExport(w http.ResponseWriter, r *http.Request) {
	request, err := decodeAuditExportRequest(w, r)
	if err != nil {
		writeAuditError(w, auditHTTPError(http.StatusBadRequest, "backend.audit.export_request_invalid", err))
		return
	}
	principal, err := h.auditPrincipal(r)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	prepared, err := h.application.PrepareBusinessExport(r.Context(), request, strings.TrimSpace(r.Header.Get("Idempotency-Key")), principal)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store, private")
	writeAuditJSON(w, http.StatusCreated, prepared)
}

func (h *AuditHandler) downloadBusinessExport(w http.ResponseWriter, r *http.Request) {
	principal, err := h.auditPrincipal(r)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	content, filename, err := h.application.DownloadBusinessExport(r.Context(), r.PathValue("token"), principal)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", auditDownloadDisposition(filename))
	w.Header().Set("Cache-Control", "no-store, private")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
