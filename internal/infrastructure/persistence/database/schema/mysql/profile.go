package mysql

import (
	"fmt"
	auditschema "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/schema"
)

type Profile struct{}

func (Profile) ColumnType(kind auditschema.ColumnKind) (string, error) {
	types := map[auditschema.ColumnKind]string{
		auditschema.Key191: "VARCHAR(191)", auditschema.Key64: "VARCHAR(64)", auditschema.Key40: "VARCHAR(40)", auditschema.Key32: "VARCHAR(32)",
		auditschema.Long: "LONGTEXT", auditschema.JSON: "JSON", auditschema.BigInt: "BIGINT",
	}
	value, ok := types[kind]
	if !ok {
		return "", fmt.Errorf("Audit MySQL column kind %q is unsupported", kind)
	}
	return value, nil
}
