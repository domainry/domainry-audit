package sqlite

import (
	"fmt"
	auditschema "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/schema"
)

type Profile struct{}

func (Profile) ColumnType(kind auditschema.ColumnKind) (string, error) {
	switch kind {
	case auditschema.Key191, auditschema.Key64, auditschema.Key40, auditschema.Key32, auditschema.Long, auditschema.JSON:
		return "TEXT", nil
	case auditschema.BigInt:
		return "BIGINT", nil
	default:
		return "", fmt.Errorf("Audit SQLite column kind %q is unsupported", kind)
	}
}
