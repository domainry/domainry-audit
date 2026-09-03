package auditstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-audit-sdk/modulehost"
	auditrepository "github.com/domainry/domainry-audit/internal/domain/audit/repository"
	"github.com/domainry/domainry-orm/query"
)

type executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type Store struct {
	db       modulehost.Database
	renderer query.Renderer
}

func NewStore(db modulehost.Database, renderer query.Renderer) *Store {
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
	actorOrgID := eventActorOrgID(event)
	queryValue, args, err := query.NewWorkspaceInsertBuilder(s.renderer, "_audit_events", event.WorkspaceID).Columns("id", "event", "object_key", "record_id", "actor_id", "actor_org_id", "role_key", "summary", "metadata_json", "before_json", "after_json", "created_at").Values(event.ID, event.Event, event.ObjectKey, event.RecordID, event.ActorID, actorOrgID, event.RoleKey, event.Summary, string(metadata), string(before), string(after), event.CreatedAt).Build()
	if err != nil {
		return err
	}
	if _, err = exec.ExecContext(ctx, queryValue, args...); err != nil {
		lookup, lookupArgs, buildErr := query.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", event.WorkspaceID).
			Columns("event", "object_key", "record_id", "actor_id", "actor_org_id", "role_key", "summary", "metadata_json", "before_json", "after_json").
			Where(query.Equal("id", event.ID)).Limit(1).Build()
		if buildErr != nil {
			return fmt.Errorf("build audit event replay lookup: %w", buildErr)
		}
		var storedEvent, objectKey, recordID, actorID, roleKey, summary, storedMetadata, storedBefore, storedAfter string
		var storedActorOrgID sql.NullString
		lookupErr := exec.QueryRow(ctx, lookup, lookupArgs...).Scan(&storedEvent, &objectKey, &recordID, &actorID, &storedActorOrgID, &roleKey, &summary, &storedMetadata, &storedBefore, &storedAfter)
		if lookupErr == nil && storedEvent == event.Event && objectKey == event.ObjectKey && recordID == event.RecordID && actorID == event.ActorID && storedActorOrgID.String == actorOrgID && roleKey == event.RoleKey && summary == event.Summary && storedMetadata == string(metadata) && storedBefore == string(before) && storedAfter == string(after) {
			return nil
		}
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, workspaceID string, queryValue contract.Query) ([]contract.Event, error) {
	if strings.TrimSpace(workspaceID) == "" {
		return nil, fmt.Errorf("audit query workspace is required")
	}
	return s.list(ctx, strings.TrimSpace(workspaceID), true, queryValue, auditrepository.AllDataScope())
}

func (s *Store) ListWithinDataScope(ctx context.Context, workspaceID string, queryValue contract.Query, scope auditrepository.DataScope) ([]contract.Event, error) {
	if strings.TrimSpace(workspaceID) == "" {
		return nil, fmt.Errorf("audit query workspace is required")
	}
	return s.list(ctx, strings.TrimSpace(workspaceID), true, queryValue, scope.Normalized())
}

func (s *Store) ListSystem(ctx context.Context, queryValue contract.Query) ([]contract.Event, error) {
	return s.list(ctx, "", false, queryValue, auditrepository.AllDataScope())
}

func (s *Store) list(ctx context.Context, workspaceID string, scoped bool, queryValue contract.Query, scope auditrepository.DataScope) ([]contract.Event, error) {
	limit := queryValue.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	predicates := []query.Predicate{}
	addEqual := func(column, value string) {
		if value = strings.TrimSpace(value); value != "" {
			predicates = append(predicates, query.Equal(column, value))
		}
	}
	addEqual("object_key", queryValue.ObjectKey)
	addEqual("record_id", queryValue.RecordID)
	addEqual("event", queryValue.Event)
	addEqual("actor_id", queryValue.ActorID)
	addEqual("role_key", queryValue.RoleKey)
	eventClassValue := auditEventClassExpression()
	switch strings.TrimSpace(queryValue.Class) {
	case contract.EventClassOperations:
		predicates = append(predicates, auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassOperations)))
	case contract.EventClassGovernance:
		operations := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassOperations))
		governance := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassGovernance))
		predicates = append(predicates, query.And(query.Not(operations), governance))
	case contract.EventClassBusiness:
		operations := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassOperations))
		governance := auditClassMarkerPredicate(eventClassValue, contract.EventClassMarkers(contract.EventClassGovernance))
		predicates = append(predicates, query.And(query.Not(operations), query.Not(governance)))
	}
	if value := strings.TrimSpace(queryValue.CreatedFrom); value != "" {
		predicates = append(predicates, query.GreaterThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(queryValue.CreatedTo); value != "" {
		predicates = append(predicates, query.LessThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(queryValue.RequestID); value != "" {
		encoded, _ := json.Marshal(value)
		predicates = append(predicates, query.LikeEscaped("metadata_json", "%"+escapeSQLLike(`"request_id":`+string(encoded))+"%"))
	}
	if value := strings.TrimSpace(queryValue.Cursor); value != "" {
		cursor, err := contract.DecodeCursor(value)
		if err != nil {
			return nil, fmt.Errorf("decode audit event cursor: %w", err)
		}
		predicates = append(predicates, query.Or(query.LessThan("created_at", cursor.CreatedAt), query.And(query.Equal("created_at", cursor.CreatedAt), query.LessThan("id", cursor.ID))))
	}
	if scopePredicate := auditEventDataScopePredicate(scope); scopePredicate != nil {
		predicates = append(predicates, scopePredicate)
	}
	var b *query.SelectBuilder
	if scoped {
		b = query.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID)
	} else {
		b = query.NewSelectBuilder(s.renderer, "_audit_events")
	}
	b.Columns("id", "workspace_id", "event", "object_key", "record_id", "actor_id", "role_key", "summary", "metadata_json", "before_json", "after_json", "created_at").OrderBy(query.Descending("created_at"), query.Descending("id")).Limit(limit)
	if len(predicates) > 0 {
		b.Where(query.And(predicates...))
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

func eventActorOrgID(event contract.Event) string {
	value, _ := event.Metadata["actor_org_id"].(string)
	return strings.TrimSpace(value)
}

func auditEventDataScopePredicate(scope auditrepository.DataScope) query.Predicate {
	scope = scope.Normalized()
	if scope.All {
		return nil
	}
	branches := make([]query.Predicate, 0, 2)
	if values := scopeValues(scope.SubjectIDs); len(values) > 0 {
		branches = append(branches, query.In("actor_id", values...))
	}
	if values := scopeValues(scope.OrganizationIDs); len(values) > 0 {
		branches = append(branches, query.In("actor_org_id", values...))
	}
	if len(branches) == 0 {
		return query.AlwaysFalse()
	}
	if len(branches) == 1 {
		return branches[0]
	}
	return query.Or(branches...)
}

func scopeValues(values []string) []any {
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result
}

func (s *Store) Options(ctx context.Context, workspaceID string, queryValue contract.OptionQuery) ([]contract.Option, error) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("audit option workspace is required")
	}
	field := strings.TrimSpace(queryValue.Field)
	switch field {
	case "record_id", "actor_id", "role_key", "event":
	default:
		return nil, fmt.Errorf("unsupported audit option field %q", field)
	}
	limit := queryValue.Limit
	if limit <= 0 {
		limit = 10
	} else if limit > 50 {
		limit = 50
	}
	predicates := []query.Predicate{query.NotEqual(field, "")}
	if value := strings.TrimSpace(queryValue.ObjectKey); value != "" {
		predicates = append(predicates, query.Equal("object_key", value))
	}
	if value := strings.TrimSpace(queryValue.CreatedFrom); value != "" {
		predicates = append(predicates, query.GreaterThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(queryValue.CreatedTo); value != "" {
		predicates = append(predicates, query.LessThanOrEqual("created_at", value))
	}
	if value := strings.TrimSpace(queryValue.Query); value != "" {
		predicates = append(predicates, query.LikeEscaped(field, "%"+escapeSQLLike(value)+"%"))
	}
	count := query.CountAll()
	statement, args, err := query.NewWorkspaceSelectBuilder(s.renderer, "_audit_events", workspaceID).Projections(query.Project(query.Column(field)), query.Project(count)).Where(query.And(predicates...)).GroupBy(query.Column(field)).OrderBy(query.DescendingExpression(count), query.Ascending(field)).Limit(limit).Build()
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

func auditEventClassExpression() query.Expression {
	return query.Lower(query.Concat(
		query.Coalesce(query.Column("event"), query.Value("")),
		query.Value(" "),
		query.Coalesce(query.Column("object_key"), query.Value("")),
	))
}

func auditClassMarkerPredicate(value query.Expression, markers []string) query.Predicate {
	predicates := make([]query.Predicate, 0, len(markers))
	for _, marker := range markers {
		predicates = append(predicates, query.LikeValueEscaped(value, "%"+escapeSQLLike(strings.ToLower(marker))+"%"))
	}
	if len(predicates) == 0 {
		return query.AlwaysFalse()
	}
	return query.Or(predicates...)
}
