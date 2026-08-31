package module

func (*AuditSurface) OpenAPIOperations() map[string]map[string]any {
	security := []any{map[string]any{"BearerAuth": []any{}}}
	queryParameters := auditOpenAPIQueryParameters()
	return map[string]map[string]any{
		"GET /business/audit-events": {
			"operationId": "listBusinessAuditEventPage", "tags": []string{"Audit Business"}, "summary": "List one actor- or record-scoped business audit page with stable keyset continuation",
			"security": security, "parameters": queryParameters, "responses": auditOpenAPIJSONResponses("200", "Bounded business audit event page", auditOpenAPIPageSchema(auditOpenAPIEventSchema("business"))),
			"x-domainry-runtime-client-method": "listBusinessAuditEventPage",
		},
		"POST /business/audit-event-exports": {
			"operationId": "prepareBusinessAuditEventExport", "tags": []string{"Audit Business"}, "summary": "Prepare immutable business audit-event CSV bytes under the current workspace and data scope",
			"security": security, "requestBody": auditOpenAPIJSONRequest(auditOpenAPIExportRequestSchema()), "responses": auditOpenAPIJSONResponses("201", "Prepared business audit-event export", auditOpenAPIExportPreparedSchema()),
		},
		"GET /business/audit-event-exports/downloads/{token}": {
			"operationId": "downloadBusinessAuditEventExport", "tags": []string{"Audit Business"}, "summary": "Download a short-lived business audit-event export after current permission and data-scope revalidation",
			"security": security, "parameters": []any{auditOpenAPIPathParameter("token", "Short-lived download token")}, "responses": map[string]any{
				"200": map[string]any{"description": "Business audit-event CSV", "content": map[string]any{"text/csv": map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}},
				"401": map[string]any{"description": "Authentication required"}, "403": map[string]any{"description": "Forbidden"}, "404": map[string]any{"description": "Export not found"}, "default": auditOpenAPIErrorResponse(),
			},
		},
		"GET /tenant-admin/audit-events": {
			"operationId": "listTenantGovernanceAuditEvents", "tags": []string{"Audit Administration"}, "summary": "List tenant governance audit events",
			"security": security, "parameters": queryParameters, "responses": auditOpenAPIJSONResponses("200", "Tenant governance audit events", auditOpenAPIPageSchema(auditOpenAPIEventSchema("governance"))),
		},
		"GET /tenant-admin/audit-events/export": {
			"operationId": "exportTenantGovernanceAuditEvents", "tags": []string{"Audit Administration"}, "summary": "Export tenant governance audit events as JSON",
			"security": security, "parameters": queryParameters, "responses": auditOpenAPIJSONResponses("200", "Tenant governance audit export", auditOpenAPIPageSchema(auditOpenAPIEventSchema("governance"))),
		},
		"GET /operations/audit-events": {
			"operationId": "listOperationsAuditEvents", "tags": []string{"Audit Operations"}, "summary": "List technical and security audit events",
			"security": security, "parameters": queryParameters, "responses": auditOpenAPIJSONResponses("200", "Operations audit events", auditOpenAPIPageSchema(auditOpenAPIEventSchema("operations"))),
		},
		"GET /operations/audit-events/export": {
			"operationId": "exportOperationsAuditEvents", "tags": []string{"Audit Operations"}, "summary": "Export technical and security audit events as JSON",
			"security": security, "parameters": queryParameters, "responses": auditOpenAPIJSONResponses("200", "Operations audit export", auditOpenAPIPageSchema(auditOpenAPIEventSchema("operations"))),
		},
	}
}

func auditOpenAPIQueryParameters() []any {
	values := []struct {
		name, description string
		schema            map[string]any
	}{
		{"object_key", "Optional business object key", map[string]any{"type": "string"}},
		{"record_id", "Optional business record identity", map[string]any{"type": "string"}},
		{"event", "Exact audit event key", map[string]any{"type": "string"}},
		{"actor_id", "Exact actor identity", map[string]any{"type": "string"}},
		{"role_key", "Exact event-time role key", map[string]any{"type": "string"}},
		{"request_id", "Exact request identity stored in audit metadata", map[string]any{"type": "string"}},
		{"created_from", "Inclusive RFC3339 lower time bound subject to retention", map[string]any{"type": "string", "format": "date-time"}},
		{"created_to", "Inclusive RFC3339 upper time bound", map[string]any{"type": "string", "format": "date-time"}},
		{"page_size", "Requested server page size", map[string]any{"type": "integer", "minimum": 1, "maximum": 200}},
		{"cursor", "Opaque keyset cursor", map[string]any{"type": "string", "maxLength": 2048}},
		{"limit", "Deprecated compatibility alias for page_size", map[string]any{"type": "integer", "minimum": 1, "maximum": 200, "deprecated": true}},
	}
	parameters := make([]any, 0, len(values))
	for _, value := range values {
		parameters = append(parameters, map[string]any{"name": value.name, "in": "query", "required": false, "description": value.description, "schema": value.schema})
	}
	return parameters
}

func auditOpenAPIEventSchema(kind string) map[string]any {
	properties := map[string]any{
		"id": map[string]any{"type": "string"}, "event": map[string]any{"type": "string"}, "object_key": map[string]any{"type": "string"},
		"record_id": map[string]any{"type": "string"}, "actor_id": map[string]any{"type": "string"}, "summary": map[string]any{"type": "string"},
		"created_at": map[string]any{"type": "string", "format": "date-time"},
	}
	switch kind {
	case "business":
		properties["before"], properties["after"] = auditOpenAPIObject(nil), auditOpenAPIObject(nil)
	case "governance":
		properties["role_key"], properties["metadata"] = map[string]any{"type": "string"}, auditOpenAPIObject(nil)
		properties["before"], properties["after"] = auditOpenAPIObject(nil), auditOpenAPIObject(nil)
	case "operations":
		properties["metadata"] = auditOpenAPIObject(nil)
	}
	return auditOpenAPIRequiredObject([]string{"id", "event", "actor_id", "summary", "created_at"}, properties)
}

func auditOpenAPIPageSchema(event map[string]any) map[string]any {
	return auditOpenAPIRequiredObject([]string{"items", "count", "page_size", "truncated", "retention_class", "retention_days"}, map[string]any{
		"items": map[string]any{"type": "array", "items": event}, "count": map[string]any{"type": "integer", "minimum": 0},
		"page_size": map[string]any{"type": "integer", "minimum": 1}, "truncated": map[string]any{"type": "boolean"},
		"next_cursor": map[string]any{"type": "string"}, "retention_class": map[string]any{"type": "string"}, "retention_days": map[string]any{"type": "integer", "minimum": 1},
	})
}

func auditOpenAPIExportRequestSchema() map[string]any {
	filter := auditOpenAPIExportFilterSchema()
	request := auditOpenAPIRequiredObject([]string{"filters"}, map[string]any{"filters": filter, "format": map[string]any{"type": "string", "enum": []string{"csv"}}})
	request["additionalProperties"] = false
	return request
}

func auditOpenAPIExportFilterSchema() map[string]any {
	filterProperties := map[string]any{}
	for _, key := range []string{"event", "object_key", "record_id", "actor_id", "role_key", "result"} {
		filterProperties[key] = map[string]any{"type": "string", "maxLength": 128}
	}
	filterProperties["created_from"] = map[string]any{"type": "string", "format": "date-time"}
	filterProperties["created_to"] = map[string]any{"type": "string", "format": "date-time"}
	filter := auditOpenAPIObject(filterProperties)
	filter["additionalProperties"] = false
	return filter
}

func auditOpenAPIExportPreparedSchema() map[string]any {
	return auditOpenAPIRequiredObject([]string{"id", "report_source", "filename", "content_sha256", "row_count", "audit_identity", "scope_sha256", "filters", "download_token", "expires_at"}, map[string]any{
		"id": map[string]any{"type": "string"}, "report_source": map[string]any{"type": "string", "enum": []string{"business_audit_events"}}, "filename": map[string]any{"type": "string"},
		"content_sha256": map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"}, "row_count": map[string]any{"type": "integer", "minimum": 1},
		"audit_identity": map[string]any{"type": "string"}, "scope_sha256": map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"},
		"filters": auditOpenAPIExportFilterSchema(), "download_token": map[string]any{"type": "string", "writeOnly": true}, "expires_at": map[string]any{"type": "string", "format": "date-time"},
	})
}

func auditOpenAPIPathParameter(name, description string) map[string]any {
	return map[string]any{"name": name, "in": "path", "required": true, "description": description, "schema": map[string]any{"type": "string"}}
}

func auditOpenAPIJSONRequest(schema map[string]any) map[string]any {
	return map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schema}}}
}

func auditOpenAPIJSONResponses(status, description string, schema map[string]any) map[string]any {
	return map[string]any{
		status: map[string]any{"description": description, "content": map[string]any{"application/json": map[string]any{"schema": schema}}},
		"400":  map[string]any{"description": "Invalid request"}, "401": map[string]any{"description": "Authentication required"}, "403": map[string]any{"description": "Forbidden"}, "404": map[string]any{"description": "Not found"}, "409": map[string]any{"description": "Conflict"}, "default": auditOpenAPIErrorResponse(),
	}
}

func auditOpenAPIErrorResponse() map[string]any {
	return map[string]any{"description": "Error", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}}
}

func auditOpenAPIObject(properties map[string]any) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	return map[string]any{"type": "object", "properties": properties}
}

func auditOpenAPIRequiredObject(required []string, properties map[string]any) map[string]any {
	result := auditOpenAPIObject(properties)
	result["required"] = required
	return result
}
