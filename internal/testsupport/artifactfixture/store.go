package artifactfixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	sharedartifact "github.com/domainry/domainry-foundation/artifact"
	sharedoperation "github.com/domainry/domainry-foundation/operation"
)

type Store struct {
	mu         sync.Mutex
	values     map[string]sharedartifact.Artifact
	bindings   map[string]sharedartifact.Binding
	content    map[string][]byte
	operations map[string]sharedoperation.Receipt
}

func New() *Store {
	return &Store{
		values: map[string]sharedartifact.Artifact{}, bindings: map[string]sharedartifact.Binding{},
		content: map[string][]byte{}, operations: map[string]sharedoperation.Receipt{},
	}
}

func key(workspaceID, id string) string {
	return strings.TrimSpace(workspaceID) + "\x00" + strings.TrimSpace(id)
}

func (s *Store) Register(_ context.Context, value sharedartifact.Artifact) (sharedartifact.Artifact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := key(value.WorkspaceID, value.ID)
	if current, found := s.values[identity]; found {
		if !reflect.DeepEqual(current, value) {
			return sharedartifact.Artifact{}, false, sharedartifact.ErrIdentityConflict
		}
		return cloneArtifact(current), false, nil
	}
	s.values[identity] = cloneArtifact(value)
	return cloneArtifact(value), true, nil
}

func (s *Store) ByID(_ context.Context, workspaceID, id string) (sharedartifact.Artifact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, found := s.values[key(workspaceID, id)]
	return cloneArtifact(value), found, nil
}

func (s *Store) ByDownloadTokenHash(_ context.Context, workspaceID, tokenHash string) (sharedartifact.Artifact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, value := range s.values {
		if value.WorkspaceID == strings.TrimSpace(workspaceID) && value.DownloadTokenSHA256 == strings.TrimSpace(tokenHash) {
			return cloneArtifact(value), true, nil
		}
	}
	return sharedartifact.Artifact{}, false, nil
}

func (s *Store) Transition(_ context.Context, workspaceID, id string, expected, next sharedartifact.Status, scan sharedartifact.ScanStatus, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := key(workspaceID, id)
	value, found := s.values[identity]
	if !found || value.Status != expected {
		return false, nil
	}
	value.Status, value.ScanStatus, value.UpdatedAt = next, scan, at
	s.values[identity] = value
	return true, nil
}

func (s *Store) Bind(_ context.Context, value sharedartifact.Binding) (sharedartifact.Binding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := key(value.WorkspaceID, value.ID)
	if current, found := s.bindings[identity]; found {
		if !reflect.DeepEqual(current, value) {
			return sharedartifact.Binding{}, false, sharedartifact.ErrBindingConflict
		}
		return cloneBinding(current), false, nil
	}
	if _, found := s.values[key(value.WorkspaceID, value.ArtifactID)]; !found {
		return sharedartifact.Binding{}, false, fmt.Errorf("artifact not found")
	}
	s.bindings[identity] = cloneBinding(value)
	return cloneBinding(value), true, nil
}

func (s *Store) Bindings(_ context.Context, workspaceID, artifactID string) ([]sharedartifact.Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []sharedartifact.Binding{}
	for _, value := range s.bindings {
		if value.WorkspaceID == strings.TrimSpace(workspaceID) && value.ArtifactID == strings.TrimSpace(artifactID) {
			result = append(result, cloneBinding(value))
		}
	}
	return result, nil
}

func (s *Store) List(_ context.Context, workspaceID string, query sharedartifact.Query) ([]sharedartifact.Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []sharedartifact.Artifact{}
	for _, value := range s.values {
		if workspaceID != "" && value.WorkspaceID != strings.TrimSpace(workspaceID) || query.Owner != "" && value.Owner != query.Owner || query.Kind != "" && value.Kind != query.Kind ||
			query.Filename != "" && value.Filename != query.Filename || query.StorageReference != "" && value.StorageReference != query.StorageReference {
			continue
		}
		if !artifactStatusContains(query.Statuses, value.Status) || !artifactScanStatusContains(query.ScanStatuses, value.ScanStatus) {
			continue
		}
		if !query.ExpiresAtOrBefore.IsZero() && (value.ExpiresAt.IsZero() || value.ExpiresAt.After(query.ExpiresAtOrBefore)) {
			continue
		}
		result = append(result, cloneArtifact(value))
	}
	if query.Limit > 0 && len(result) > query.Limit {
		result = result[:query.Limit]
	}
	return result, nil
}

func artifactStatusContains(values []sharedartifact.Status, value sharedartifact.Status) bool {
	if len(values) == 0 {
		return true
	}
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func artifactScanStatusContains(values []sharedartifact.ScanStatus, value sharedartifact.ScanStatus) bool {
	if len(values) == 0 {
		return true
	}
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (s *Store) Update(_ context.Context, mutation sharedartifact.Mutation) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := key(mutation.WorkspaceID, mutation.ID)
	value, found := s.values[identity]
	if !found || value.Owner != mutation.Owner || value.Kind != mutation.Kind || value.Status != mutation.ExpectedStatus || value.ScanStatus != mutation.ExpectedScanStatus || !mutation.ExpectedUpdatedAt.IsZero() && !value.UpdatedAt.Equal(mutation.ExpectedUpdatedAt) {
		return false, nil
	}
	value.Status, value.ScanStatus, value.ExpiresAt, value.UpdatedAt = mutation.Status, mutation.ScanStatus, mutation.ExpiresAt, mutation.UpdatedAt
	value.Metadata = append([]byte(nil), mutation.Metadata...)
	s.values[identity] = value
	return true, nil
}

func (s *Store) PutImmutable(_ context.Context, workspaceID, identity string, content []byte) (sharedartifact.ContentInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reference := "memory:" + strings.TrimSpace(identity)
	storageKey := key(workspaceID, reference)
	if current, found := s.content[storageKey]; found && !bytes.Equal(current, content) {
		return sharedartifact.ContentInfo{}, fmt.Errorf("artifact content identity conflict")
	}
	s.content[storageKey] = append([]byte(nil), content...)
	digest := sha256.Sum256(content)
	return sharedartifact.ContentInfo{Reference: reference, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content))}, nil
}

func (s *Store) Open(_ context.Context, workspaceID, reference string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, found := s.content[key(workspaceID, reference)]
	if !found {
		return nil, sharedartifact.ErrContentNotFound
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), content...))), nil
}

func (s *Store) Stat(_ context.Context, workspaceID, reference string) (sharedartifact.ContentInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, found := s.content[key(workspaceID, reference)]
	if !found {
		return sharedartifact.ContentInfo{}, sharedartifact.ErrContentNotFound
	}
	digest := sha256.Sum256(content)
	return sharedartifact.ContentInfo{Reference: reference, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content))}, nil
}

func (s *Store) Delete(_ context.Context, workspaceID, reference string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.content, key(workspaceID, reference))
	return nil
}

func (s *Store) Claim(_ context.Context, command sharedoperation.Command) (sharedoperation.Receipt, bool, error) {
	if err := command.Validate(); err != nil {
		return sharedoperation.Receipt{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := operationKey(command.Scope, command.Owner, command.Kind, command.IdempotencyKey)
	if current, found := s.operations[identity]; found {
		if current.Command.RequestFingerprint != command.RequestFingerprint {
			return sharedoperation.Receipt{}, false, sharedoperation.ErrIdempotencyConflict
		}
		return cloneOperation(current), false, nil
	}
	receipt := sharedoperation.Receipt{Command: command, Status: sharedoperation.StatusStarted}
	s.operations[identity] = cloneOperation(receipt)
	return cloneOperation(receipt), true, nil
}

func (s *Store) Complete(_ context.Context, completion sharedoperation.Completion) error {
	if err := completion.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := operationKey(completion.Scope, completion.Owner, completion.Kind, completion.IdempotencyKey)
	receipt, found := s.operations[identity]
	if !found || receipt.Command.ID != completion.ID || receipt.Command.RequestFingerprint != completion.RequestFingerprint || receipt.Status != sharedoperation.StatusStarted {
		return fmt.Errorf("shared Operation is not started")
	}
	receipt.Status = sharedoperation.StatusSucceeded
	receipt.Result = append(json.RawMessage(nil), completion.Result...)
	s.operations[identity] = cloneOperation(receipt)
	return nil
}

func operationKey(scope sharedoperation.Scope, owner, kind, idempotencyKey string) string {
	return strings.TrimSpace(scope.WorkspaceID) + "\x00" + strings.TrimSpace(scope.SystemPurpose) + "\x00" + strings.TrimSpace(owner) + "\x00" + strings.TrimSpace(kind) + "\x00" + strings.TrimSpace(idempotencyKey)
}

func cloneArtifact(value sharedartifact.Artifact) sharedartifact.Artifact {
	value.Metadata = append([]byte(nil), value.Metadata...)
	return value
}

func cloneBinding(value sharedartifact.Binding) sharedartifact.Binding {
	value.Metadata = append([]byte(nil), value.Metadata...)
	return value
}

func cloneOperation(value sharedoperation.Receipt) sharedoperation.Receipt {
	value.Result = append(json.RawMessage(nil), value.Result...)
	return value
}

var _ sharedoperation.Store = (*Store)(nil)
