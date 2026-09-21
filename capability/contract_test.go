package capability

import (
	"testing"

	audithttp "github.com/domainry/domainry-audit/internal/transport/http/module"
	"github.com/domainry/domainry-foundation/modulecapability"
	"github.com/domainry/domainry-foundation/modulecapability/contracttest"
)

func TestAuditCapabilityContractTracksOwnerRoutesWithoutInventedAuthoringValidation(t *testing.T) {
	binding, err := Open(Inputs{})
	if err != nil {
		t.Fatal(err)
	}
	contracttest.VerifyBinding(t, binding)
	summary, err := binding.CapabilitySummary(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Identity.SupportedDeploymentModes) != 1 || summary.Identity.SupportedDeploymentModes[0] != modulecapability.DeploymentModeModule {
		t.Fatalf("Audit topology=%v", summary.Identity.SupportedDeploymentModes)
	}
	operations := 0
	for _, category := range summary.Categories {
		operations += category.OperationCount
		if len(category.ValidationScopes) != 0 {
			t.Fatalf("Audit runtime request DTOs leaked into model validation scopes: %v", category.ValidationScopes)
		}
	}
	if operations != len((&audithttp.AuditHTTPAdapter{}).Routes()) {
		t.Fatalf("Audit disclosure operations=%d routes=%d", operations, len((&audithttp.AuditHTTPAdapter{}).Routes()))
	}
}
