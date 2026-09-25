package exportstore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/domainry/domainry-audit/internal/testsupport/artifactfixture"
)

func TestExportFilterInstantsAreNumericInsideArtifactMetadata(t *testing.T) {
	backend := artifactfixture.New()
	store := NewStore(backend, backend, backend, backend)
	from := time.Date(2026, 9, 25, 12, 0, 0, 0, time.FixedZone("local", 8*3600))
	to := from.Add(time.Hour)
	artifact := exportStoreTestArtifact()
	artifact.Filters.CreatedFrom = from.Format(time.RFC3339Nano)
	artifact.Filters.CreatedTo = to.Format(time.RFC3339Nano)
	created, fresh, err := store.CreateOrGetExport(t.Context(), artifact)
	if err != nil || !fresh {
		t.Fatalf("created=%+v fresh=%v err=%v", created, fresh, err)
	}
	shared, found, err := backend.ByID(t.Context(), created.WorkspaceID, created.ID)
	if err != nil || !found {
		t.Fatalf("shared=%+v found=%v err=%v", shared, found, err)
	}
	var metadata struct {
		Filters struct {
			CreatedFrom int64 `json:"created_from"`
			CreatedTo   int64 `json:"created_to"`
		} `json:"filters"`
	}
	if err := json.Unmarshal(shared.Metadata, &metadata); err != nil || metadata.Filters.CreatedFrom != from.UnixMilli() || metadata.Filters.CreatedTo != to.UnixMilli() {
		t.Fatalf("metadata=%+v err=%v payload=%s", metadata, err, shared.Metadata)
	}
	if created.Filters.CreatedFrom != from.UTC().Format(time.RFC3339) || created.Filters.CreatedTo != to.UTC().Format(time.RFC3339) {
		t.Fatalf("returned filters=%+v", created.Filters)
	}
}
