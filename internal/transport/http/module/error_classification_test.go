package module

import (
	"net/http/httptest"
	"testing"

	"github.com/domainry/domainry-foundation/apperror"
)

type classificationCapture struct {
	*httptest.ResponseRecorder
	kind, code string
}

func (capture *classificationCapture) RecordError(kind, code string) {
	capture.kind, capture.code = kind, code
}

func TestAuditErrorClassificationMatrix(t *testing.T) {
	tests := []struct {
		kind apperror.ErrorKind
		code string
	}{
		{apperror.KindUnavailable, "backend.audit.database_unavailable"},
		{apperror.KindConflict, "backend.audit.export_fence_rejected"},
		{apperror.KindBadRequest, "backend.audit.query_invalid"},
		{apperror.KindForbidden, "backend.audit.permission_denied"},
	}
	for _, test := range tests {
		capture := &classificationCapture{ResponseRecorder: httptest.NewRecorder()}
		writeAuditError(capture, apperror.New(test.kind, test.code, nil, nil))
		if capture.kind != string(test.kind) || capture.code != test.code {
			t.Fatalf("want=%q/%q got=%q/%q", test.kind, test.code, capture.kind, capture.code)
		}
	}
}
