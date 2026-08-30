package auditstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	ormbuilder "github.com/domainry/domainry-orm/query"
)

func (s *Store) PreviewSubject(ctx context.Context, workspaceID, identity string) (json.RawMessage, error) {
	statement, args, err := ormbuilder.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).Projections(ormbuilder.Project(ormbuilder.CountAll())).Where(ormbuilder.Equal("actor_id", identity)).Build()
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
	projections := make([]ormbuilder.Projection, 0, len(columns))
	for _, column := range columns {
		projections = append(projections, ormbuilder.Project(ormbuilder.Coalesce(ormbuilder.Column(column), ormbuilder.Value(""))))
	}
	statement, args, err := ormbuilder.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).Projections(projections...).Where(ormbuilder.Equal("actor_id", identity)).OrderBy(ormbuilder.Ascending("created_at")).Build()
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
	sum := sha256.Sum256([]byte(workspaceID + "\x00" + identity))
	anonymous := "erased-" + hex.EncodeToString(sum[:12])
	statement, args, err := ormbuilder.NewWorkspaceUpdateBuilder(s.renderer, "_audit_events", workspaceID).Set("actor_id", anonymous).Where(ormbuilder.Equal("actor_id", identity)).Build()
	if err != nil {
		return nil, err
	}
	result, err := s.db.ExecContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"anonymized_audit_references": changed, "event_integrity_preserved": true, "at": time.Now().UTC()})
}
