package sqlite

import (
	"fmt"
	auditmigration "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/migration"
)

type Profile struct{}

func (Profile) ColumnType(kind auditmigration.ColumnKind) (string, error) {
	switch kind {
	case auditmigration.Key191, auditmigration.Key64, auditmigration.Key40, auditmigration.Key32, auditmigration.Long, auditmigration.JSON:
		return "TEXT", nil
	case auditmigration.BigInt:
		return "BIGINT", nil
	default:
		return "", fmt.Errorf("Audit SQLite column kind %q is unsupported", kind)
	}
}
