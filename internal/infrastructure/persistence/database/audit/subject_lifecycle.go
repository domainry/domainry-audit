package auditstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	columns := []string{"id", "event", "object_key", "record_id", "summary", "created_at"}
	projections := make([]query.Projection, 0, len(columns))
	for _, column := range columns {
		projections = append(projections, query.Project(query.Coalesce(query.Column(column), query.Value(""))))
	}
	statement, args, err := query.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).Projections(projections...).Where(query.Equal("actor_id", identity)).OrderBy(query.Ascending("created_at")).Build()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]string{}
	for rows.Next() {
		var id, event, objectKey, recordID, summary, createdAt string
		if err := rows.Scan(&id, &event, &objectKey, &recordID, &summary, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]string{"id": id, "event": event, "object_key": objectKey, "record_id": recordID, "summary": summary, "created_at": createdAt})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(items)
}

func (s *Store) EraseSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	workspaceID, identity = strings.TrimSpace(workspaceID), strings.TrimSpace(identity)
	if workspaceID == "" || identity == "" {
		return nil, fmt.Errorf("audit subject identity is required")
	}
	sum := sha256.Sum256([]byte(workspaceID + "\x00" + identity))
	anonymous := "erased-" + hex.EncodeToString(sum[:12])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	candidate, candidateArgs, err := query.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).
		Projections(query.Project(query.CountAll())).Where(query.Equal("actor_id", identity)).Build()
	if err != nil {
		return nil, err
	}
	var expected int64
	if err := tx.QueryRowContext(ctx, candidate, candidateArgs...).Scan(&expected); err != nil {
		return nil, err
	}
	statement, args, err := query.NewWorkspaceUpdateBuilder(s.renderer, "_audit_events", workspaceID).
		Set("actor_id", anonymous).Where(query.Equal("actor_id", identity)).Build()
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != expected {
		return nil, fmt.Errorf("audit subject candidate set changed during anonymization")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"anonymized_audit_references": changed, "event_integrity_preserved": true, "at": time.Now().UTC()})
}
