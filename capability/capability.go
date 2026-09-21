// Package capability exposes Audit's source-owned capability contract without
// opening persistence or export services.
package capability

import (
	"github.com/domainry/domainry-foundation/modulecapability"
)

type Inputs struct{}

func Open(inputs Inputs) (*modulecapability.StaticBinding, error) {
	return openContract(inputs)
}
