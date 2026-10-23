package module

import (
	"errors"
	"net/http"
	"strings"

	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditapp "github.com/domainry/domainry-audit/internal/application/audit"
	"github.com/domainry/domainry-foundation/requestcontext"
	identitysdk "github.com/domainry/domainry-identity-sdk"
)

type AuditHandler struct {
	application *auditapp.AuditQueryApplicationService
}

func NewAuditHandler(application *auditapp.AuditQueryApplicationService) (*AuditHandler, error) {
	if application == nil {
		return nil, errors.New("Audit HTTP adapter application is unavailable")
	}
	return &AuditHandler{application: application}, nil
}

func (h *AuditHandler) auditPrincipal(r *http.Request) (modulehost.AuditPrincipal, error) {
	identity, ok := identitysdk.PrincipalFromContext(r.Context())
	if !ok {
		return modulehost.AuditPrincipal{}, auditHTTPError(http.StatusUnauthorized, "backend.auth.token_required", nil)
	}
	return h.application.ResolvePrincipal(r.Context(), modulehost.AuditPrincipalRequest{
		Identity: identity, BusinessProfileKey: strings.TrimSpace(r.Header.Get("X-Business-Profile-Key")),
		BusinessProfileID: strings.TrimSpace(r.Header.Get("X-Business-Profile-ID")), RequestID: requestcontext.RequestID(r.Context()),
	})
}
