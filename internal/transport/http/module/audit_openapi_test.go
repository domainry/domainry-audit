package module

import "testing"

func TestAuditEventOpenAPIMatchesSDKWireContract(t *testing.T) {
	for _, kind := range []string{"business", "governance", "operations"} {
		schema := auditOpenAPIEventSchema(kind)
		properties := schema["properties"].(map[string]any)
		for _, key := range []string{"id", "workspace_id", "event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata", "before", "after", "created_at"} {
			if properties[key] == nil {
				t.Errorf("%s audit event schema is missing %s", kind, key)
			}
		}
		for _, key := range []string{"metadata", "before", "after"} {
			value := properties[key].(map[string]any)
			if value["additionalProperties"] != true {
				t.Errorf("%s audit event %s must preserve arbitrary redacted JSON values", kind, key)
			}
		}
	}
}
