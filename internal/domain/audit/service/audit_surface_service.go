package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
	"github.com/domainry/domainry-foundation/secrets"
)

type SurfaceKind string

const (
	SurfaceBusiness   SurfaceKind = "business"
	SurfaceGovernance SurfaceKind = "governance"
	SurfaceOperations SurfaceKind = "operations"

	BusinessRetentionDays   = 365
	GovernanceRetentionDays = 2555
	OperationsRetentionDays = 90
	BusinessMaxPageSize     = 200
)

type SurfacePlan struct {
	Kind           SurfaceKind
	Query          contract.Query
	PageSize       int
	RetentionClass string
	RetentionDays  int
}

type SurfaceEvent struct {
	ID, Event, ObjectKey, RecordID, ActorID, RoleKey, Summary, CreatedAt string
	Metadata, Before, After                                              map[string]any
}

type SurfaceResult struct {
	Items                      []SurfaceEvent
	Count, PageSize            int
	Truncated                  bool
	NextCursor, RetentionClass string
	RetentionDays              int
}

func PlanSurface(kind SurfaceKind, query contract.Query, actorID string, now time.Time) (SurfacePlan, error) {
	days, class := 0, ""
	switch kind {
	case SurfaceBusiness:
		days, class = BusinessRetentionDays, "business_history"
		if strings.TrimSpace(query.ObjectKey) == "" || strings.TrimSpace(query.RecordID) == "" {
			query.ActorID = actorID
		}
		if query.Limit > BusinessMaxPageSize {
			query.Limit = BusinessMaxPageSize
		}
		if query.Cursor != "" {
			if _, err := contract.DecodeAuditEventCursor(query.Cursor); err != nil {
				return SurfacePlan{}, fmt.Errorf("audit cursor invalid: %w", err)
			}
		}
	case SurfaceGovernance:
		days, class = GovernanceRetentionDays, "tenant_governance"
	case SurfaceOperations:
		days, class = OperationsRetentionDays, "technical_security"
	default:
		return SurfacePlan{}, fmt.Errorf("unsupported audit surface %q", kind)
	}
	cutoff := now.UTC().AddDate(0, 0, -days)
	if current, err := time.Parse(time.RFC3339, strings.TrimSpace(query.CreatedFrom)); err != nil || current.Before(cutoff) {
		query.CreatedFrom = cutoff.Format(time.RFC3339)
	}
	if query.Limit <= 0 || query.Limit > 1000 {
		query.Limit = 200
	}
	pageSize := query.Limit
	if kind == SurfaceBusiness {
		query.Limit = pageSize + 1
	}
	query.Class = string(kind)
	return SurfacePlan{Kind: kind, Query: query, PageSize: pageSize, RetentionClass: class, RetentionDays: days}, nil
}

func ProjectSurface(events []contract.Event, plan SurfacePlan) SurfaceResult {
	truncated := plan.Kind == SurfaceBusiness && len(events) > plan.PageSize
	if truncated {
		events = events[:plan.PageSize]
	}
	next := ""
	if truncated && len(events) > 0 {
		next = contract.EncodeAuditEventCursor(events[len(events)-1])
	}
	items := make([]SurfaceEvent, 0, len(events))
	for _, event := range events {
		if contract.ClassifyAuditEvent(event) != string(plan.Kind) {
			continue
		}
		item := SurfaceEvent{
			ID: event.ID, Event: event.Event, ObjectKey: event.ObjectKey, RecordID: event.RecordID,
			ActorID: event.ActorID, RoleKey: event.RoleKey, Summary: event.Summary, CreatedAt: event.CreatedAt,
		}
		switch plan.Kind {
		case SurfaceBusiness:
			item.Before, item.After = secrets.RedactMap(event.Before), secrets.RedactMap(event.After)
		case SurfaceGovernance:
			item.Metadata = secrets.RedactMap(event.Metadata)
			item.Before, item.After = secrets.RedactMap(event.Before), secrets.RedactMap(event.After)
		case SurfaceOperations:
			item.Metadata = secrets.RedactMap(event.Metadata)
		}
		items = append(items, item)
	}
	return SurfaceResult{
		Items: items, Count: len(items), PageSize: plan.PageSize, Truncated: truncated, NextCursor: next,
		RetentionClass: plan.RetentionClass, RetentionDays: plan.RetentionDays,
	}
}
