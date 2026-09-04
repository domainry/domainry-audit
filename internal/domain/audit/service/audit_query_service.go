package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/secrets"
)

type EventClass string

const (
	EventClassBusiness   EventClass = "business"
	EventClassGovernance EventClass = "governance"
	EventClassOperations EventClass = "operations"

	BusinessRetentionDays   = 365
	GovernanceRetentionDays = 2555
	OperationsRetentionDays = 90
	BusinessMaxPageSize     = 200
)

type QueryPlan struct {
	Kind           EventClass
	Query          contract.Query
	PageSize       int
	RetentionClass string
	RetentionDays  int
}

type QueryEvent struct {
	ID, Event, ObjectKey, RecordID, ActorID, RoleKey, Summary, CreatedAt string
	Metadata, Before, After                                              map[string]any
}

type QueryResult struct {
	Items                      []QueryEvent
	Count, PageSize            int
	Truncated                  bool
	NextCursor, RetentionClass string
	RetentionDays              int
}

func PlanQuery(kind EventClass, query contract.Query, _ string, now time.Time) (QueryPlan, error) {
	days, class := 0, ""
	switch kind {
	case EventClassBusiness:
		days, class = BusinessRetentionDays, "business_history"
		if query.Limit > BusinessMaxPageSize {
			query.Limit = BusinessMaxPageSize
		}
		if query.Cursor != "" {
			if _, err := contract.DecodeAuditEventCursor(query.Cursor); err != nil {
				return QueryPlan{}, fmt.Errorf("audit cursor invalid: %w", err)
			}
		}
	case EventClassGovernance:
		days, class = GovernanceRetentionDays, "tenant_governance"
	case EventClassOperations:
		days, class = OperationsRetentionDays, "technical_security"
	default:
		return QueryPlan{}, fmt.Errorf("unsupported audit event class %q", kind)
	}
	cutoff := now.UTC().AddDate(0, 0, -days)
	if current, err := time.Parse(time.RFC3339, strings.TrimSpace(query.CreatedFrom)); err != nil || current.Before(cutoff) {
		query.CreatedFrom = cutoff.Format(time.RFC3339)
	}
	if query.Limit <= 0 || query.Limit > 1000 {
		query.Limit = 200
	}
	pageSize := query.Limit
	if kind == EventClassBusiness {
		query.Limit = pageSize + 1
	}
	query.Class = string(kind)
	return QueryPlan{Kind: kind, Query: query, PageSize: pageSize, RetentionClass: class, RetentionDays: days}, nil
}

func ProjectQuery(events []contract.Event, plan QueryPlan) QueryResult {
	truncated := plan.Kind == EventClassBusiness && len(events) > plan.PageSize
	if truncated {
		events = events[:plan.PageSize]
	}
	next := ""
	if truncated && len(events) > 0 {
		next = contract.EncodeAuditEventCursor(events[len(events)-1])
	}
	items := make([]QueryEvent, 0, len(events))
	for _, event := range events {
		if contract.ClassifyAuditEvent(event) != string(plan.Kind) {
			continue
		}
		item := QueryEvent{
			ID: event.ID, Event: event.Event, ObjectKey: event.ObjectKey, RecordID: event.RecordID,
			ActorID: event.ActorID, RoleKey: event.RoleKey, Summary: event.Summary, CreatedAt: event.CreatedAt,
		}
		switch plan.Kind {
		case EventClassBusiness:
			item.Before, item.After = secrets.RedactMap(event.Before), secrets.RedactMap(event.After)
		case EventClassGovernance:
			item.Metadata = secrets.RedactMap(event.Metadata)
			item.Before, item.After = secrets.RedactMap(event.Before), secrets.RedactMap(event.After)
		case EventClassOperations:
			item.Metadata = secrets.RedactMap(event.Metadata)
		}
		items = append(items, item)
	}
	return QueryResult{
		Items: items, Count: len(items), PageSize: plan.PageSize, Truncated: truncated, NextCursor: next,
		RetentionClass: plan.RetentionClass, RetentionDays: plan.RetentionDays,
	}
}
