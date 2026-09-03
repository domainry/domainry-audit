package repository

import (
	"context"

	"github.com/domainry/domainry-audit-sdk/contract"
)

// ExportArtifactRepository is the domain-owned persistence port. Embedded mode
// uses the host database; a future SaaS mode may bind another implementation.
type ExportArtifactRepository interface {
	contract.ExportStore
	ExportByTokenHashWithinDataScope(context.Context, string, string, string, DataScope) (contract.ExportArtifact, bool, error)
	RecordExportDownloadWithinDataScope(context.Context, string, string, string, string, DataScope) (bool, error)
}
