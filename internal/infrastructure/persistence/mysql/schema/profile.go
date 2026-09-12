package mysql

import (
	"fmt"
	auditmigration "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/migration"
)

type Profile struct{}

// InnoDB appends primary-key columns to secondary indexes. Omitting the final
// id from this wide nonunique index keeps every key value intact and preserves
// its effective cursor order, while fitting utf8mb4's 3072-byte key limit.
func (Profile) IndexColumns(table string, columns []string) []string {
	if table == "_audit_events" && len(columns) == 5 && columns[0] == "workspace_id" && columns[4] == "id" {
		return columns[:4]
	}
	return columns
}

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
