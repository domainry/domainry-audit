package exportstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	sharedartifact "github.com/domainry/domainry-foundation/artifact"
	sharedoperation "github.com/domainry/domainry-foundation/operation"
)

const (
	exportOperationOwner     = "audit"
	exportOperationKind      = "audit.export.prepare"
	exportOperationActionKey = "audit.business.export.prepare"
)

type Store struct {
	artifacts  sharedartifact.ManagedStore
	content    sharedartifact.ContentStore
	writer     sharedartifact.ContentWriter
	operations sharedoperation.Store
}

type exportMetadata struct {
	RoleKey          string                `json:"role_key"`
	Filters          contract.ExportFilter `json:"filters"`
	ScopeSHA256      string                `json:"scope_sha256"`
	RowCount         int                   `json:"row_count"`
	AuditIdentity    string                `json:"audit_identity"`
	Status           string                `json:"status"`
	DownloadCount    int                   `json:"download_count,omitempty"`
	LastDownloadedAt int64                 `json:"last_downloaded_at,omitempty"`
}

func NewStore(artifacts sharedartifact.ManagedStore, content sharedartifact.ContentStore, writer sharedartifact.ContentWriter, operations sharedoperation.Store) *Store {
	return &Store{artifacts: artifacts, content: content, writer: writer, operations: operations}
}

func (s *Store) CreateOrGetExport(ctx context.Context, value contract.ExportArtifact) (contract.ExportArtifact, bool, error) {
	if err := validateExport(value); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if err := s.ready(); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	value.ID = exportID(value)
	if current, found, err := s.byID(ctx, value.WorkspaceID, value.ID); err != nil {
		return contract.ExportArtifact{}, false, err
	} else if found {
		if !sameExportRequest(current, value) {
			return contract.ExportArtifact{}, false, contract.ErrExportIdempotencyConflict
		}
		if err := s.bindRequester(ctx, current); err != nil {
			return contract.ExportArtifact{}, false, err
		}
		if err := s.ensurePrepareOperation(ctx, current); err != nil {
			return contract.ExportArtifact{}, false, err
		}
		if err := s.bindOperation(ctx, current); err != nil {
			return contract.ExportArtifact{}, false, err
		}
		return current, false, nil
	}

	createdAt, err := time.Parse(time.RFC3339Nano, value.CreatedAt)
	if err != nil {
		return contract.ExportArtifact{}, false, fmt.Errorf("parse audit export creation time: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	if err != nil {
		return contract.ExportArtifact{}, false, fmt.Errorf("parse audit export expiry: %w", err)
	}
	info, err := s.writer.PutImmutable(ctx, value.WorkspaceID, "audit-export:"+value.ID, value.Content)
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if !strings.EqualFold(strings.TrimSpace(info.SHA256), value.ContentSHA256) || info.Size != int64(len(value.Content)) || strings.TrimSpace(info.Reference) == "" {
		err = fmt.Errorf("audit export content store returned mismatched integrity evidence")
		return contract.ExportArtifact{}, false, s.cleanupUnregisteredContent(ctx, value.WorkspaceID, info.Reference, err)
	}
	metadata, err := json.Marshal(exportMetadata{
		RoleKey: value.RoleKey, Filters: value.Filters, ScopeSHA256: value.ScopeSHA256,
		RowCount: value.RowCount, AuditIdentity: value.AuditIdentity, Status: value.Status,
	})
	if err != nil {
		return contract.ExportArtifact{}, false, s.cleanupUnregisteredContent(ctx, value.WorkspaceID, info.Reference, err)
	}
	registered, created, err := s.artifacts.Register(ctx, sharedartifact.Artifact{
		ID: value.ID, WorkspaceID: value.WorkspaceID, Owner: sharedartifact.OwnerAudit, Kind: "export",
		IdempotencyKey: value.IdempotencyKey, CreatedBy: value.RequesterUserID,
		Filename: value.Filename, MediaType: "text/csv", ContentSHA256: value.ContentSHA256,
		SizeBytes: int64(len(value.Content)), StorageReference: info.Reference,
		Status: sharedartifact.StatusAvailable, ExpiresAt: expiresAt, ScanStatus: sharedartifact.ScanNotRequired,
		DownloadTokenSHA256: value.TokenSHA256, AuthorizationScopeSHA256: value.AuthorizationScopeSHA256,
		Metadata: metadata, CreatedAt: createdAt, UpdatedAt: createdAt,
	})
	if err != nil {
		if current, found, readErr := s.byID(ctx, value.WorkspaceID, value.ID); readErr == nil && found {
			if !sameExportRequest(current, value) {
				return contract.ExportArtifact{}, false, contract.ErrExportIdempotencyConflict
			}
			if bindErr := s.bindRequester(ctx, current); bindErr != nil {
				return contract.ExportArtifact{}, false, bindErr
			}
			if operationErr := s.ensurePrepareOperation(ctx, current); operationErr != nil {
				return contract.ExportArtifact{}, false, operationErr
			}
			if bindErr := s.bindOperation(ctx, current); bindErr != nil {
				return contract.ExportArtifact{}, false, bindErr
			}
			return current, false, nil
		}
		return contract.ExportArtifact{}, false, s.cleanupUnregisteredContent(ctx, value.WorkspaceID, info.Reference, err)
	}
	stored, _, err := exportFromShared(registered)
	if err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if err := s.bindRequester(ctx, stored); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if err := s.ensurePrepareOperation(ctx, stored); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	if err := s.bindOperation(ctx, stored); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	return stored, created, nil
}

func (s *Store) cleanupUnregisteredContent(ctx context.Context, workspaceID, reference string, cause error) error {
	if strings.TrimSpace(reference) == "" {
		return cause
	}
	values, err := s.artifacts.List(ctx, strings.TrimSpace(workspaceID), sharedartifact.Query{StorageReference: strings.TrimSpace(reference), Limit: 1})
	if err != nil {
		return errors.Join(cause, fmt.Errorf("verify audit export content registration before cleanup: %w", err))
	}
	if len(values) != 0 {
		return cause
	}
	if err = s.content.Delete(context.WithoutCancel(ctx), strings.TrimSpace(workspaceID), strings.TrimSpace(reference)); err != nil && !errors.Is(err, sharedartifact.ErrContentNotFound) {
		return errors.Join(cause, fmt.Errorf("delete unregistered audit export content: %w", err))
	}
	return cause
}

func (s *Store) ExportByTokenHash(ctx context.Context, workspaceID, tokenHash string) (contract.ExportArtifact, bool, error) {
	return s.exportByTokenHashWithinDataScope(ctx, workspaceID, tokenHash, "", auditrepository.AllDataScope())
}

func (s *Store) ExportByTokenHashWithinDataScope(ctx context.Context, workspaceID, tokenHash, requesterUserID string, scope auditrepository.DataScope) (contract.ExportArtifact, bool, error) {
	return s.exportByTokenHashWithinDataScope(ctx, workspaceID, tokenHash, requesterUserID, scope)
}

func (s *Store) exportByTokenHashWithinDataScope(ctx context.Context, workspaceID, tokenHash, requesterUserID string, scope auditrepository.DataScope) (contract.ExportArtifact, bool, error) {
	if err := s.ready(); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	artifact, found, err := s.artifacts.ByDownloadTokenHash(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(tokenHash))
	if err != nil || !found {
		return contract.ExportArtifact{}, found, err
	}
	if !auditExportArtifact(artifact) || !exportRequesterAllowed(artifact.CreatedBy, requesterUserID, scope) {
		return contract.ExportArtifact{}, false, nil
	}
	return exportFromShared(artifact)
}

// ExportContentWithinDataScope is deliberately separate from token lookup.
// The application may call it only after validating the signed token, current
// authorization scope and expiry. The store re-reads the Artifact immediately
// before I/O so a terminal transition or expiry cannot open the Blob.
func (s *Store) ExportContentWithinDataScope(ctx context.Context, workspaceID, artifactID, tokenHash, requesterUserID string, authorizedAt time.Time, scope auditrepository.DataScope) ([]byte, bool, error) {
	if err := s.ready(); err != nil {
		return nil, false, err
	}
	artifact, found, err := s.artifacts.ByID(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(artifactID))
	if err != nil || !found {
		return nil, found, err
	}
	if !auditExportArtifact(artifact) ||
		!exportRequesterAllowed(artifact.CreatedBy, requesterUserID, scope) ||
		artifact.DownloadTokenSHA256 != strings.TrimSpace(tokenHash) ||
		authorizedAt.IsZero() || !authorizedAt.UTC().Before(artifact.ExpiresAt.UTC()) {
		return nil, false, nil
	}
	reader, err := s.content.Open(ctx, artifact.WorkspaceID, artifact.StorageReference)
	if err != nil {
		return nil, false, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, artifact.SizeBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(content)) != artifact.SizeBytes {
		return nil, false, fmt.Errorf("%w: size", auditrepository.ErrExportContentIntegrity)
	}
	digest := sha256.Sum256(content)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), artifact.ContentSHA256) {
		return nil, false, fmt.Errorf("%w: SHA-256", auditrepository.ErrExportContentIntegrity)
	}
	return content, true, nil
}

func (s *Store) RecordExportDownload(ctx context.Context, workspaceID, artifactID, downloadedAt string) (bool, error) {
	return s.recordExportDownloadWithinDataScope(ctx, workspaceID, artifactID, "", downloadedAt, auditrepository.AllDataScope())
}

func (s *Store) RecordExportDownloadWithinDataScope(ctx context.Context, workspaceID, artifactID, requesterUserID, downloadedAt string, scope auditrepository.DataScope) (bool, error) {
	return s.recordExportDownloadWithinDataScope(ctx, workspaceID, artifactID, requesterUserID, downloadedAt, scope)
}

func (s *Store) recordExportDownloadWithinDataScope(ctx context.Context, workspaceID, artifactID, requesterUserID, downloadedAt string, scope auditrepository.DataScope) (bool, error) {
	value, found, err := s.artifacts.ByID(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(artifactID))
	if err != nil {
		return false, err
	}
	if !found || !auditExportArtifact(value) || !exportRequesterAllowed(value.CreatedBy, requesterUserID, scope) {
		return false, fmt.Errorf("audit export artifact not found")
	}
	var metadata exportMetadata
	if err := json.Unmarshal(value.Metadata, &metadata); err != nil {
		return false, err
	}
	if metadata.DownloadCount != 0 {
		return false, nil
	}
	observedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(downloadedAt))
	if err != nil {
		return false, fmt.Errorf("parse audit export download time: %w", err)
	}
	if !observedAt.After(value.UpdatedAt) {
		observedAt = value.UpdatedAt.Add(time.Nanosecond)
	}
	metadata.DownloadCount, metadata.LastDownloadedAt = 1, observedAt.UTC().UnixMilli()
	raw, err := json.Marshal(metadata)
	if err != nil {
		return false, err
	}
	return s.artifacts.Update(ctx, sharedartifact.Mutation{
		WorkspaceID: value.WorkspaceID, ID: value.ID, Owner: value.Owner, Kind: value.Kind,
		ExpectedStatus: value.Status, ExpectedScanStatus: value.ScanStatus, ExpectedUpdatedAt: value.UpdatedAt,
		Status: value.Status, ScanStatus: value.ScanStatus, ExpiresAt: value.ExpiresAt,
		Metadata: raw, UpdatedAt: observedAt,
	})
}

func (s *Store) byID(ctx context.Context, workspaceID, id string) (contract.ExportArtifact, bool, error) {
	value, found, err := s.artifacts.ByID(ctx, strings.TrimSpace(workspaceID), strings.TrimSpace(id))
	if err != nil || !found {
		return contract.ExportArtifact{}, found, err
	}
	if !auditExportArtifact(value) {
		return contract.ExportArtifact{}, false, nil
	}
	return exportFromShared(value)
}

func exportFromShared(value sharedartifact.Artifact) (contract.ExportArtifact, bool, error) {
	var metadata exportMetadata
	if err := json.Unmarshal(value.Metadata, &metadata); err != nil {
		return contract.ExportArtifact{}, false, err
	}
	lastDownloadedAt := ""
	if metadata.LastDownloadedAt != 0 {
		lastDownloadedAt = time.UnixMilli(metadata.LastDownloadedAt).UTC().Format(time.RFC3339Nano)
	}
	result := contract.ExportArtifact{
		ID: value.ID, WorkspaceID: value.WorkspaceID, RequesterUserID: value.CreatedBy,
		RoleKey: metadata.RoleKey, IdempotencyKey: value.IdempotencyKey, Filters: metadata.Filters,
		ScopeSHA256: metadata.ScopeSHA256, AuthorizationScopeSHA256: value.AuthorizationScopeSHA256,
		TokenSHA256: value.DownloadTokenSHA256, Filename: value.Filename,
		ContentSHA256: value.ContentSHA256, RowCount: metadata.RowCount,
		AuditIdentity: metadata.AuditIdentity, Status: metadata.Status,
		CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: value.ExpiresAt.UTC().Format(time.RFC3339Nano),
		DownloadCount: metadata.DownloadCount, LastDownloadedAt: lastDownloadedAt,
	}
	return result, true, nil
}

func (s *Store) bindRequester(ctx context.Context, value contract.ExportArtifact) error {
	createdAt, err := time.Parse(time.RFC3339Nano, value.CreatedAt)
	if err != nil {
		return err
	}
	_, _, err = s.artifacts.Bind(ctx, sharedartifact.Binding{
		ID: value.ID + ":requester", WorkspaceID: value.WorkspaceID, ArtifactID: value.ID,
		Owner: sharedartifact.OwnerAudit, Kind: sharedartifact.BindingSubject,
		ResourceType: "audit_export_requester", ResourceID: value.RequesterUserID, CreatedAt: createdAt,
	})
	return err
}

func (s *Store) bindOperation(ctx context.Context, value contract.ExportArtifact) error {
	createdAt, err := time.Parse(time.RFC3339Nano, value.CreatedAt)
	if err != nil {
		return err
	}
	_, _, err = s.artifacts.Bind(ctx, sharedartifact.Binding{
		ID: value.ID + ":operation", WorkspaceID: value.WorkspaceID, ArtifactID: value.ID,
		Owner: sharedartifact.OwnerAudit, Kind: sharedartifact.BindingOperation,
		ResourceType: "operation", ResourceID: exportOperationID(value.ID), CreatedAt: createdAt,
	})
	return err
}

type exportOperationResult struct {
	ArtifactID    string `json:"artifact_id"`
	ContentSHA256 string `json:"content_sha256"`
	ScopeSHA256   string `json:"scope_sha256"`
}

func (s *Store) ensurePrepareOperation(ctx context.Context, value contract.ExportArtifact) error {
	createdAt, err := time.Parse(time.RFC3339Nano, value.CreatedAt)
	if err != nil {
		return err
	}
	fingerprint := exportOperationFingerprint(value)
	command := sharedoperation.Command{
		ID: exportOperationID(value.ID),
		Scope: sharedoperation.Scope{
			WorkspaceID: value.WorkspaceID, ResourceType: "audit_export", ResourceID: value.ID,
		},
		Owner: exportOperationOwner, Kind: exportOperationKind, ActionKey: exportOperationActionKey,
		IdempotencyKey: value.IdempotencyKey, RequestFingerprint: fingerprint,
		RequestedBy: value.RequesterUserID, Reason: "prepare audit export", Reference: value.ID,
		StatusURL: "/api/audit/exports/" + value.ID, CreatedAt: createdAt,
	}
	receipt, _, err := s.operations.Claim(ctx, command)
	if errors.Is(err, sharedoperation.ErrIdempotencyConflict) {
		return contract.ErrExportIdempotencyConflict
	}
	if err != nil {
		return err
	}
	if err := validatePrepareOperationReceipt(receipt, command, value); err != nil {
		return err
	}
	if receipt.Status == sharedoperation.StatusSucceeded {
		return nil
	}
	result, err := json.Marshal(exportOperationResult{ArtifactID: value.ID, ContentSHA256: value.ContentSHA256, ScopeSHA256: value.ScopeSHA256})
	if err != nil {
		return err
	}
	completion := sharedoperation.Completion{
		ID: command.ID, Scope: command.Scope, Owner: command.Owner, Kind: command.Kind,
		IdempotencyKey: command.IdempotencyKey, RequestFingerprint: command.RequestFingerprint,
		Result: result, CompletedAt: createdAt,
	}
	if err := s.operations.Complete(ctx, completion); err == nil {
		return nil
	}
	// A concurrent exact replay may have completed the same command between
	// Claim and Complete. Re-read through the idempotent Claim boundary and
	// accept only the exact succeeded receipt.
	receipt, _, claimErr := s.operations.Claim(ctx, command)
	if claimErr != nil {
		return claimErr
	}
	if err := validatePrepareOperationReceipt(receipt, command, value); err != nil {
		return err
	}
	if receipt.Status != sharedoperation.StatusSucceeded {
		return fmt.Errorf("audit export prepare Operation remained in status %q", receipt.Status)
	}
	return nil
}

func validatePrepareOperationReceipt(receipt sharedoperation.Receipt, command sharedoperation.Command, value contract.ExportArtifact) error {
	if receipt.Command.ID != command.ID || receipt.Command.Owner != command.Owner || receipt.Command.Kind != command.Kind || receipt.Command.RequestFingerprint != command.RequestFingerprint {
		return contract.ErrExportIdempotencyConflict
	}
	if receipt.Status == sharedoperation.StatusStarted {
		return nil
	}
	if receipt.Status != sharedoperation.StatusSucceeded {
		return fmt.Errorf("audit export prepare Operation has unsupported status %q", receipt.Status)
	}
	var result exportOperationResult
	if err := json.Unmarshal(receipt.Result, &result); err != nil {
		return fmt.Errorf("decode audit export prepare Operation result: %w", err)
	}
	if result.ArtifactID != value.ID || result.ContentSHA256 != value.ContentSHA256 || result.ScopeSHA256 != value.ScopeSHA256 {
		return fmt.Errorf("audit export prepare Operation result does not match the Artifact")
	}
	return nil
}

func exportOperationID(artifactID string) string {
	return "audit_export_prepare:" + strings.TrimSpace(artifactID)
}

func exportOperationFingerprint(value contract.ExportArtifact) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		"domainry-audit/export-prepare/v1", value.WorkspaceID, value.RequesterUserID,
		value.ScopeSHA256, value.AuthorizationScopeSHA256,
	}, "\x00")))
	return hex.EncodeToString(digest[:])
}

func (s *Store) ready() error {
	if s == nil || s.artifacts == nil || s.content == nil || s.writer == nil || s.operations == nil {
		return fmt.Errorf("shared Audit artifact storage is unavailable")
	}
	return nil
}

func auditExportArtifact(value sharedartifact.Artifact) bool {
	return value.Owner == sharedartifact.OwnerAudit && value.Kind == "export" && value.Status == sharedartifact.StatusAvailable
}

func exportRequesterAllowed(createdBy, requesterUserID string, scope auditrepository.DataScope) bool {
	createdBy, requesterUserID = strings.TrimSpace(createdBy), strings.TrimSpace(requesterUserID)
	if requesterUserID != "" && createdBy != requesterUserID {
		return false
	}
	scope = scope.Normalized()
	if scope.All {
		return true
	}
	for _, subjectID := range scope.SubjectIDs {
		if strings.TrimSpace(subjectID) == createdBy {
			return true
		}
	}
	return false
}

func validateExport(value contract.ExportArtifact) error {
	if strings.TrimSpace(value.WorkspaceID) == "" || strings.TrimSpace(value.RequesterUserID) == "" || strings.TrimSpace(value.IdempotencyKey) == "" || strings.TrimSpace(value.ScopeSHA256) == "" || strings.TrimSpace(value.AuthorizationScopeSHA256) == "" || strings.TrimSpace(value.TokenSHA256) == "" || strings.TrimSpace(value.ContentSHA256) == "" || strings.TrimSpace(value.AuditIdentity) == "" || value.RowCount < 1 || len(value.Content) == 0 {
		return fmt.Errorf("complete audit export identity, scope, and content are required")
	}
	return nil
}

func sameExportRequest(left, right contract.ExportArtifact) bool {
	return left.ScopeSHA256 == right.ScopeSHA256 && left.AuthorizationScopeSHA256 == right.AuthorizationScopeSHA256
}

func exportID(value contract.ExportArtifact) string {
	sum := sha256.Sum256([]byte(value.WorkspaceID + "\x00" + value.RequesterUserID + "\x00audit_events\x00" + value.IdempotencyKey))
	return "audexp_" + hex.EncodeToString(sum[:16])
}
