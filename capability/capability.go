// Package capability exposes Audit's source-owned capability contract without
// opening persistence or export services.
package capability

import (
	audithttp "github.com/domainry/domainry-audit/internal/transport/http/module"
	"github.com/domainry/domainry-foundation/modulecapability"
)

type Inputs struct{}

func Open(Inputs) (*modulecapability.StaticBinding, error) {
	return audithttp.NewCapabilityBinding()
}
