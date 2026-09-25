package auditstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-orm/query"
)

func (s *Store) PreviewSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	statement, args, err := query.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).Projections(query.Project(query.CountAll())).Where(query.Equal("actor_id", identity)).Build()
	if err != nil {
		return nil, err
	}
	var count int64
	if err := s.db.QueryRowContext(ctx, statement, args...).Scan(&count); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]int64{"audit_references": count})
}

func (s *Store) ExportSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	columns := []string{"id", "event", "object_key", "record_id", "summary"}
	projections := make([]query.Projection, 0, len(columns))
	for _, column := range columns {
		projections = append(projections, query.Project(query.Coalesce(query.Column(column), query.Value(""))))
	}
	projections = append(projections, query.Project(query.Column("created_at")))
	statement, args, err := query.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).Projections(projections...).Where(query.Equal("actor_id", identity)).OrderBy(query.Ascending("created_at")).Build()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, event, objectKey, recordID, summary string
		var createdAt int64
		if err := rows.Scan(&id, &event, &objectKey, &recordID, &summary, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "event": event, "object_key": objectKey, "record_id": recordID, "summary": summary, "created_at": createdAt})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(items)
}

func (s *Store) EraseSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	return s.EraseSubjectResources(ctx, workspaceID, identity, nil)
}

func (s *Store) EraseSubjectResources(ctx context.Context, workspaceID, identity string, resources []contract.SubjectResource) (json.RawMessage, error) {
	workspaceID, identity = strings.TrimSpace(workspaceID), strings.TrimSpace(identity)
	if workspaceID == "" || identity == "" {
		return nil, fmt.Errorf("audit subject identity is required")
	}
	predicates := []query.Predicate{query.Equal("actor_id", identity)}
	for _, resource := range resources {
		if strings.TrimSpace(resource.ObjectKey) == "" || strings.TrimSpace(resource.RecordID) == "" {
			return nil, fmt.Errorf("audit subject resource scope is required")
		}
		predicates = append(predicates, query.And(query.Equal("object_key", resource.ObjectKey), query.Equal("record_id", resource.RecordID)))
	}
	sum := sha256.Sum256([]byte(workspaceID + "\x00" + identity))
	anonymous := "erased-" + hex.EncodeToString(sum[:12])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var changed int64
	// One source-owned transaction covers actor data and every declared record.
	// Keep event identity and time, but remove historical personal snapshots.
	for _, predicate := range predicates {
		statement, args, err := query.NewWorkspaceUpdateBuilder(s.renderer, "_audit_events", workspaceID).
			Set("summary", "[erased]").Set("metadata_json", "{}").Set("before_json", "null").Set("after_json", "null").Where(predicate).Build()
		if err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(ctx, statement, args...)
		if err != nil {
			return nil, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		changed += count
	}
	statement, args, err := query.NewWorkspaceUpdateBuilder(s.renderer, "_audit_events", workspaceID).
		Set("actor_id", anonymous).Set("actor_org_id", nil).Set("role_key", "").Where(query.Equal("actor_id", identity)).Build()
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, statement, args...); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"redacted_audit_matches": changed, "event_identity_preserved": true, "at": time.Now().UTC().UnixMilli()})
}
