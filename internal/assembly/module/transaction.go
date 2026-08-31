package module

import (
	"context"
	"fmt"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditstore "github.com/domainry/domainry-audit/internal/infrastructure/persistence/database/audit"
)

// AppendPreparedWithin is the narrow integration seam for host stores that
// already own a larger SQL transaction. It does not open a connection or run DDL.
func AppendPreparedWithin(ctx context.Context, dialect modulehost.Dialect, tx contract.Transaction, event contract.AuditEvent) error {
	if tx == nil {
		return fmt.Errorf("audit host transaction is required")
	}
	if dialect == nil {
		return fmt.Errorf("audit host ORM dialect is required")
	}
	return auditstore.NewStore(nil, dialect).AppendPreparedWithin(ctx, tx, event)
}
