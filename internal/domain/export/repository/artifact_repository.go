package repository

import "github.com/domainry/domainry-audit-sdk/contract"

// ArtifactRepository is the domain-owned persistence port. Embedded mode uses
// the host database; SaaS may bind another durable implementation.
type ArtifactRepository interface {
	contract.ExportStore
}
