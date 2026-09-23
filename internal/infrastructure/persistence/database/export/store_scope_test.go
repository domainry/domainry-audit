package exportstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	"github.com/domainry/domainry-audit/internal/testsupport/artifactfixture"
	sharedartifact "github.com/domainry/domainry-foundation/artifact"
	sharedoperation "github.com/domainry/domainry-foundation/operation"
)

func TestExportRegistrationFailureDeletesOnlyUnreferencedContent(t *testing.T) {
	backend := artifactfixture.New()
	registerErr := errors.New("register failed")
	artifacts := &failingExportArtifactStore{ManagedStore: backend, err: registerErr}
	store := NewStore(artifacts, backend, backend, backend)
	value := exportStoreTestArtifact()
	if _, _, err := store.CreateOrGetExport(t.Context(), value); !errors.Is(err, registerErr) {
		t.Fatalf("create err=%v", err)
	}
	reference := "memory:audit-export:" + exportID(value)
	if _, err := backend.Stat(t.Context(), value.WorkspaceID, reference); !errors.Is(err, sharedartifact.ErrContentNotFound) {
		t.Fatalf("unregistered content remains: %v", err)
	}

	artifacts.commitThenFail = true
	if replay, created, err := store.CreateOrGetExport(t.Context(), value); err != nil || created || replay.ID != exportID(value) {
		t.Fatalf("uncertain register replay=%#v created=%v err=%v", replay, created, err)
	}
	if _, err := backend.Stat(t.Context(), value.WorkspaceID, reference); err != nil {
		t.Fatalf("registered content was deleted: %v", err)
	}
}

type failingExportArtifactStore struct {
	sharedartifact.ManagedStore
	err            error
	commitThenFail bool
}

func (s *failingExportArtifactStore) Register(ctx context.Context, value sharedartifact.Artifact) (sharedartifact.Artifact, bool, error) {
	if s.commitThenFail {
		persisted, created, err := s.ManagedStore.Register(ctx, value)
		if err != nil {
			return persisted, created, err
		}
		return persisted, created, s.err
	}
	return sharedartifact.Artifact{}, false, s.err
}

func TestExportArtifactsUseSharedMetadataContentAndRequesterBinding(t *testing.T) {
	backend := artifactfixture.New()
	contentStore := &observedContentStore{delegate: backend}
	store := NewStore(backend, contentStore, backend, backend)
	artifact, created, err := store.CreateOrGetExport(t.Context(), exportStoreTestArtifact())
	if err != nil || !created {
		t.Fatalf("create artifact=%#v created=%v err=%v", artifact, created, err)
	}

	shared, found, err := backend.ByID(t.Context(), artifact.WorkspaceID, artifact.ID)
	if err != nil || !found || shared.Owner != sharedartifact.OwnerAudit || shared.Kind != "export" || shared.StorageReference == "" || len(shared.Metadata) == 0 {
		t.Fatalf("shared artifact=%#v found=%v err=%v", shared, found, err)
	}
	bindings, err := backend.Bindings(t.Context(), artifact.WorkspaceID, artifact.ID)
	if err != nil || len(bindings) != 2 {
		t.Fatalf("artifact bindings=%#v err=%v", bindings, err)
	}
	bindingKinds := map[string]string{}
	for _, binding := range bindings {
		bindingKinds[binding.Kind] = binding.ResourceID
	}
	if bindingKinds[sharedartifact.BindingSubject] != "requester" || bindingKinds[sharedartifact.BindingOperation] != exportOperationID(artifact.ID) {
		t.Fatalf("artifact bindings=%#v", bindings)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, artifact.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	operation, claimed, err := backend.Claim(t.Context(), sharedoperation.Command{
		ID: exportOperationID(artifact.ID), Scope: sharedoperation.Scope{WorkspaceID: artifact.WorkspaceID, ResourceType: "audit_export", ResourceID: artifact.ID},
		Owner: exportOperationOwner, Kind: exportOperationKind, ActionKey: exportOperationActionKey,
		IdempotencyKey: artifact.IdempotencyKey, RequestFingerprint: exportOperationFingerprint(artifact),
		RequestedBy: artifact.RequesterUserID, Reason: "prepare audit export", Reference: artifact.ID,
		StatusURL: "/api/audit/exports/" + artifact.ID, CreatedAt: createdAt,
	})
	if err != nil || claimed || operation.Status != sharedoperation.StatusSucceeded {
		t.Fatalf("prepare operation=%#v claimed=%v err=%v", operation, claimed, err)
	}

	if _, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "other", auditrepository.OwnerDataScope("other")); err != nil || found {
		t.Fatalf("another requester read artifact: found=%v err=%v", found, err)
	}
	if _, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "requester", auditrepository.DataScope{OrganizationIDs: []string{"org-a"}}); err != nil || found {
		t.Fatalf("organization-only scope inferred artifact ownership: found=%v err=%v", found, err)
	}
	if current, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "requester", auditrepository.OwnerDataScope("requester")); err != nil || !found || current.ID != artifact.ID || len(current.Content) != 0 {
		t.Fatalf("requester artifact=%#v found=%v err=%v", current, found, err)
	}
	if contentStore.opens != 0 {
		t.Fatalf("metadata lookup opened Blob %d times", contentStore.opens)
	}
	authorizedAt := time.Date(2026, 9, 3, 0, 10, 0, 0, time.UTC)
	if content, found, err := store.ExportContentWithinDataScope(t.Context(), "workspace", artifact.ID, artifact.TokenSHA256, "requester", authorizedAt, auditrepository.OwnerDataScope("requester")); err != nil || !found || string(content) != "content" {
		t.Fatalf("authorized content=%q found=%v err=%v", content, found, err)
	}
	if contentStore.opens != 1 {
		t.Fatalf("authorized content opened Blob %d times", contentStore.opens)
	}
	if _, found, err := store.ExportContentWithinDataScope(t.Context(), "workspace", artifact.ID, "wrong-token-hash", "requester", authorizedAt, auditrepository.OwnerDataScope("requester")); err != nil || found {
		t.Fatalf("wrong token hash content found=%v err=%v", found, err)
	}
	if _, found, err := store.ExportContentWithinDataScope(t.Context(), "workspace", artifact.ID, artifact.TokenSHA256, "requester", time.Date(2026, 9, 3, 0, 15, 0, 0, time.UTC), auditrepository.OwnerDataScope("requester")); err != nil || found {
		t.Fatalf("expired content found=%v err=%v", found, err)
	}
	if _, found, err := store.ExportContentWithinDataScope(t.Context(), "workspace", artifact.ID, artifact.TokenSHA256, "other", authorizedAt, auditrepository.OwnerDataScope("other")); err != nil || found {
		t.Fatalf("foreign requester content found=%v err=%v", found, err)
	}
	if contentStore.opens != 1 {
		t.Fatalf("denied content opened Blob; total opens=%d", contentStore.opens)
	}

	if recorded, err := store.RecordExportDownloadWithinDataScope(t.Context(), "workspace", artifact.ID, "other", "2026-09-03T00:01:00Z", auditrepository.OwnerDataScope("other")); err == nil || recorded {
		t.Fatalf("another requester recorded download: recorded=%v err=%v", recorded, err)
	}
	if recorded, err := store.RecordExportDownloadWithinDataScope(t.Context(), "workspace", artifact.ID, "requester", "2026-09-03T00:01:00Z", auditrepository.OwnerDataScope("requester")); err != nil || !recorded {
		t.Fatalf("requester download record=%v err=%v", recorded, err)
	}
	if recorded, err := store.RecordExportDownloadWithinDataScope(t.Context(), "workspace", artifact.ID, "requester", "2026-09-03T00:02:00Z", auditrepository.OwnerDataScope("requester")); err != nil || recorded {
		t.Fatalf("repeat download record=%v err=%v", recorded, err)
	}
	if _, found, err := store.ExportByTokenHashWithinDataScope(t.Context(), "workspace", artifact.TokenSHA256, "requester", auditrepository.AllDataScope()); err != nil || !found {
		t.Fatalf("all artifact lookup found=%v err=%v", found, err)
	}
}

type observedContentStore struct {
	delegate sharedartifact.ContentStore
	opens    int
}

func (s *observedContentStore) Open(ctx context.Context, workspaceID, reference string) (io.ReadCloser, error) {
	s.opens++
	return s.delegate.Open(ctx, workspaceID, reference)
}

func (s *observedContentStore) Stat(ctx context.Context, workspaceID, reference string) (sharedartifact.ContentInfo, error) {
	return s.delegate.Stat(ctx, workspaceID, reference)
}

func (s *observedContentStore) Delete(ctx context.Context, workspaceID, reference string) error {
	return s.delegate.Delete(ctx, workspaceID, reference)
}

func exportStoreTestArtifact() contract.ExportArtifact {
	content := []byte("content")
	digest := sha256.Sum256(content)
	return contract.ExportArtifact{
		WorkspaceID: "workspace", RequesterUserID: "requester", RoleKey: "member", IdempotencyKey: "idempotency",
		ScopeSHA256: "scope", AuthorizationScopeSHA256: "authorization", TokenSHA256: "token", Filename: "audit.csv",
		ContentSHA256: hex.EncodeToString(digest[:]), RowCount: 1, Content: content, AuditIdentity: "audit", Status: "prepared",
		CreatedAt: "2026-09-03T00:00:00Z", ExpiresAt: "2026-09-03T00:15:00Z",
	}
}
