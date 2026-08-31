package module

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
)

func auditEventQuery(r *http.Request) contract.Query {
	values := r.URL.Query()
	pageSize, _ := strconv.Atoi(strings.TrimSpace(values.Get("page_size")))
	if pageSize == 0 {
		pageSize, _ = strconv.Atoi(strings.TrimSpace(values.Get("limit")))
	}
	return contract.Query{
		ObjectKey: strings.TrimSpace(values.Get("object_key")), RecordID: strings.TrimSpace(values.Get("record_id")),
		Event: strings.TrimSpace(values.Get("event")), ActorID: strings.TrimSpace(values.Get("actor_id")),
		RoleKey: strings.TrimSpace(values.Get("role_key")), RequestID: strings.TrimSpace(values.Get("request_id")),
		CreatedFrom: strings.TrimSpace(values.Get("created_from")), CreatedTo: strings.TrimSpace(values.Get("created_to")),
		Limit: pageSize, Cursor: strings.TrimSpace(values.Get("cursor")),
	}
}

func decodeAuditExportRequest(w http.ResponseWriter, r *http.Request) (contract.ExportRequest, error) {
	var request contract.ExportRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return contract.ExportRequest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return contract.ExportRequest{}, errors.New("request body contains multiple JSON values")
		}
		return contract.ExportRequest{}, err
	}
	return request, nil
}
