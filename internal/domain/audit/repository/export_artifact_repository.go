package repository

import (
	"context"
	"errors"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
)

var ErrExportContentIntegrity = errors.New("audit export content integrity mismatch")

// ExportArtifactRepository is the domain-owned persistence port. Embedded mode
// uses the host database; a future SaaS mode may bind another implementation.
type ExportArtifactRepository interface {
	contract.ExportStore
	ExportByTokenHashWithinDataScope(context.Context, string, string, string, DataScope) (contract.ExportArtifact, bool, error)
	ExportContentWithinDataScope(context.Context, string, string, string, string, time.Time, DataScope) ([]byte, bool, error)
	RecordExportDownloadWithinDataScope(context.Context, string, string, string, string, DataScope) (bool, error)
}
