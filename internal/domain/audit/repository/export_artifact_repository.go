package repository

import "github.com/domainry/domainry-audit-sdk/contract"

// ExportArtifactRepository is the domain-owned persistence port. Embedded mode
// uses the host database; a future SaaS mode may bind another implementation.
type ExportArtifactRepository interface {
	contract.ExportStore
}
