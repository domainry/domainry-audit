package mysql

import (
	"fmt"
	auditmigration "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/migration"
)

type Profile struct{}

func (Profile) ColumnType(kind auditmigration.ColumnKind) (string, error) {
	types := map[auditmigration.ColumnKind]string{
		auditmigration.Key191: "VARCHAR(191)", auditmigration.Key64: "VARCHAR(64)", auditmigration.Key40: "VARCHAR(40)", auditmigration.Key32: "VARCHAR(32)",
		auditmigration.Long: "LONGTEXT", auditmigration.JSON: "JSON", auditmigration.BigInt: "BIGINT",
	}
	value, ok := types[kind]
	if !ok {
		return "", fmt.Errorf("Audit MySQL column kind %q is unsupported", kind)
	}
	return value, nil
}
