package mysql

import (
	"fmt"
	auditmigration "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/migration"
	ormschema "github.com/domainry/domainry-orm/schema"
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

func (profile Profile) ColumnTypeFor(name string, kind auditmigration.ColumnKind) (string, error) {
	if name == "id" || name == "created_at" {
		return "VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin", nil
	}
	return profile.ColumnType(kind)
}

func (Profile) AdaptColumn(name string, column ormschema.ColumnDefinition) ormschema.ColumnDefinition {
	if name == "id" || name == "created_at" {
		return ormschema.Column(name, ormschema.TextKey(191)).NotNull().CharacterSet("ascii").Collation("ascii_bin")
	}
	return column
}
