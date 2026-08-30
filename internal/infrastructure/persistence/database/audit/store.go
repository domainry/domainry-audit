package auditstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	ormbuilder "github.com/domainry/domainry-orm/query"
)

type executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Store struct {
	db       modulehost.Database
	renderer ormbuilder.Renderer
}

func NewStore(db modulehost.Database, renderer ormbuilder.Renderer) *Store {
	return &Store{db: db, renderer: renderer}
}

func (s *Store) AppendPrepared(ctx context.Context, event contract.Event) error {
	if err := validatePrepared(event); err != nil {
		return err
	}
	return s.insert(ctx, databaseExecutor{s.db}, event)
}

func (s *Store) AppendPreparedWithin(ctx context.Context, tx contract.Transaction, event contract.Event) error {
	if tx == nil {
		return fmt.Errorf("audit host transaction is required")
	}
	if err := validatePrepared(event); err != nil {
		return err
	}
	return s.insert(ctx, hostTransactionExecutor{tx}, event)
}

func validatePrepared(event contract.Event) error {
	if strings.TrimSpace(event.WorkspaceID) == "" {
		return fmt.Errorf("prepared audit event is incomplete")
	}
	return nil
}

type eventExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRow(context.Context, string, ...any) contract.Row
}

type databaseExecutor struct{ executor }

func (e databaseExecutor) QueryRow(ctx context.Context, q string, args ...any) contract.Row {
	return e.QueryRowContext(ctx, q, args...)
}
func (e databaseExecutor) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return e.executor.ExecContext(ctx, q, args...)
}

type hostTransactionExecutor struct{ contract.Transaction }

func (e hostTransactionExecutor) QueryRow(ctx context.Context, q string, args ...any) contract.Row {
	return e.Transaction.QueryRowContext(ctx, q, args...)
}
func (e hostTransactionExecutor) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	r, err := e.Transaction.ExecContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return resultAdapter{r}, nil
}

type resultAdapter struct{ contract.Result }

func (resultAdapter) LastInsertId() (int64, error) { return 0, nil }

func (s *Store) insert(ctx context.Context, exec eventExecutor, event contract.Event) error {
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}
	before, err := json.Marshal(event.Before)
	if err != nil {
		return fmt.Errorf("encode audit before: %w", err)
	}
	after, err := json.Marshal(event.After)
	if err != nil {
		return fmt.Errorf("encode audit after: %w", err)
	}
	query, args, err := ormbuilder.NewWorkspaceInsertBuilder(s.renderer, "_audit_events", event.WorkspaceID).Columns("id", "event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata_json", "before_json", "after_json", "created_at").Values(event.ID, event.Event, event.ObjectKey, event.RecordID, event.ActorID, event.RoleKey, event.Summary, string(metadata), string(before), string(after), event.CreatedAt).Build()
	if err != nil {
		return err
	}
	if _, err = exec.ExecContext(ctx, query, args...); err != nil {
		lookup, lookupArgs, buildErr := ormbuilder.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", event.WorkspaceID).
			Columns("event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata_json", "before_json", "after_json").
			Where(ormbuilder.Equal("id", event.ID)).Limit(1).Build()
		if buildErr != nil {
			return fmt.Errorf("build audit event replay lookup: %w", buildErr)
		}
		var storedEvent, objectKey, recordID, actorID, roleKey, summary, storedMetadata, storedBefore, storedAfter string
		lookupErr := exec.QueryRow(ctx, lookup, lookupArgs...).Scan(&storedEvent, &objectKey, &recordID, &actorID, &roleKey, &summary, &storedMetadata, &storedBefore, &storedAfter)
		if lookupErr == nil && storedEvent == event.Event && objectKey == event.ObjectKey && recordID == event.RecordID && actorID == event.ActorID && roleKey == event.RoleKey && summary == event.Summary && storedMetadata == string(metadata) && storedBefore == string(before) && storedAfter == string(after) {
			return nil
		}
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, workspaceID string, query contract.Query) ([]contract.Event, error) {
	if strings.TrimSpace(workspaceID) == "" {
		return nil, fmt.Errorf("audit query workspace is required")
	}
	return s.list(ctx, strings.TrimSpace(workspaceID), true, query)
}

func (s *Store) ListSystem(ctx context.Context, query contract.Query) ([]contract.Event, error) {
	return s.list(ctx, "", false, query)
}

func (s *Store) list(ctx context.Context, workspaceID string, scoped bool, query contract.Query) ([]contract.Event, error) {
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	predicates := []ormbuilder.Predicate{}
	addEqual := func(column, value string) {
		if value = strings.TrimSpace(value); value != "" {
			predicates = append(predicates, ormbuilder.Equal(column, value))
		}
	}
	addEqual("object_key", query.ObjectKey)
	addEqual("record_id", query.RecordID)
	addEqual("event", query.Event)
	addEqual("actor_id", query.ActorID)
	addEqual("role_key", query.RoleKey)
	eventClassValue := auditEventClassExpression()
	switch strings.TrimSpace(query.Class) {
	case contract.EventClassOperations:
		predicates = append(predicates, auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassOperations)))
	case contract.EventClassGovernance:
		operations := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassOperations))
		governance := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassGovernance))
		predicates = append(predicates, ormbuilder.And(ormbuilder.Not(operations), governance))
	case contract.EventClassBusiness:
		operations := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassOperations))
		governance := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassGovernance))
		predicates = append(predicates, ormbuilder.And(ormbuilder.Not(operations), ormbuilder.Not(governance)))
	}
	if value := strings.TrimSpace(query.CreatedFrom); value != "" {
		predicates = append(predicates, ormbuilder.GreaterThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(query.CreatedTo); value != "" {
		predicates = append(predicates, ormbuilder.LessThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(query.RequestID); value != "" {
		encoded, _ := json.Marshal(value)
		predicates = append(predicates, ormbuilder.LikeEscaped("metadata_json", "%"+escapeSQLLike(`"request_id":`+string(encoded))+"%"))
	}
	if value := strings.TrimSpace(query.Cursor); value != "" {
		cursor, err := contract.DecodeCursor(value)
		if err != nil {
			return nil, fmt.Errorf("decode audit event cursor: %w", err)
		}
		predicates = append(predicates, ormbuilder.Or(ormbuilder.LessThan("created_at", cursor.CreatedAt), ormbuilder.And(ormbuilder.Equal("created_at", cursor.CreatedAt), ormbuilder.LessThan("id", cursor.ID))))
	}
	var b *ormbuilder.SelectBuilder
	if scoped {
		b = ormbuilder.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID)
	} else {
		b = ormbuilder.NewSelectBuilder(s.renderer, "_audit_events")
	}
	b.Columns("id", "workspace_id", "event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata_json", "before_json", "after_json", "created_at").OrderBy(ormbuilder.Descending("created_at"), ormbuilder.Descending("id")).Limit(limit)
	if len(predicates) > 0 {
		b.Where(ormbuilder.And(predicates...))
	}
	statement, args, err := b.Build()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []contract.Event{}
	for rows.Next() {
		var e contract.Event
		var metadata, before, after, created string
		if err := rows.Scan(&e.ID, &e.WorkspaceID, &e.Event, &e.ObjectKey, &e.RecordID, &e.ActorID, &e.RoleKey, &e.Summary, &metadata, &before, &after, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(metadata), &e.Metadata)
		_ = json.Unmarshal([]byte(before), &e.Before)
		_ = json.Unmarshal([]byte(after), &e.After)
		e.CreatedAt = created
		result = append(result, e)
	}
	return result, rows.Err()
}

func (s *Store) Options(ctx context.Context, workspaceID string, query contract.OptionQuery) ([]contract.Option, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("audit option workspace is required")
	}
	field := strings.TrimSpace(query.Field)
	switch field {
	case "record_id", "actor_id", "role_key", "event":
	default:
		return nil, fmt.Errorf("unsupported audit option field %q", field)
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 10
	} else if limit > 50 {
		limit = 50
	}
	predicates := []ormbuilder.Predicate{ormbuilder.NotEqual(field, "")}
	if value := strings.TrimSpace(query.ObjectKey); value != "" {
		predicates = append(predicates, ormbuilder.Equal("object_key", value))
	}
	if value := strings.TrimSpace(query.CreatedFrom); value != "" {
		predicates = append(predicates, ormbuilder.GreaterThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(query.CreatedTo); value != "" {
		predicates = append(predicates, ormbuilder.LessThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(query.Query); value != "" {
		predicates = append(predicates, ormbuilder.LikeEscaped(field, "%"+escapeSQLLike(value)+"%"))
	}
	count := ormbuilder.CountAll()
	statement, args, err := ormbuilder.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).Projections(ormbuilder.Project(ormbuilder.Column(field)), ormbuilder.Project(count)).Where(ormbuilder.And(predicates...)).GroupBy(ormbuilder.Column(field)).OrderBy(ormbuilder.DescendingExpression(count), ormbuilder.Ascending(field)).Limit(limit).Build()
	if err != nil {
		return nil, fmt.Errorf("build audit option list: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit options: %w", err)
	}
	defer rows.Close()
	options := []contract.Option{}
	for rows.Next() {
		var option contract.Option
		if err := rows.Scan(&option.Value, &option.Count); err != nil {
			return nil, err
		}
		option.Label = option.Value
		options = append(options, option)
	}
	return options, rows.Err()
}

func escapeSQLLike(value string) string {
	value = strings.ReplaceAll(value, "~", "~~")
	value = strings.ReplaceAll(value, "%", "~%")
	return strings.ReplaceAll(value, "_", "~_")
}

func auditEventClassExpression() ormbuilder.Expression {
	return ormbuilder.Lower(ormbuilder.Concat(
		ormbuilder.Coalesce(ormbuilder.Column("event"), ormbuilder.Value("")),
		ormbuilder.Value(" "),
		ormbuilder.Coalesce(ormbuilder.Column("object_key"), ormbuilder.Value("")),
	))
}

func auditClassMarkerPredicate(value ormbuilder.Expression, markers []string) ormbuilder.Predicate {
	predicates := make([]ormbuilder.Predicate, 0, len(markers))
	for _, marker := range markers {
		predicates = append(predicates, ormbuilder.LikeValueEscaped(value, "%"+escapeSQLLike(strings.ToLower(marker))+"%"))
	}
	if len(predicates) == 0 {
		return ormbuilder.AlwaysFalse()
	}
	return ormbuilder.Or(predicates...)
}
