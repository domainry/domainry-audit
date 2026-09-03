package service

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/domainry/domainry-audit-sdk/contract"
)

const retentionDays = 365

var filterValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$`)

func NormalizeExportFilters(request contract.ExportRequest, _ contract.ExportPrincipal, now time.Time) (contract.ExportFilter, error) {
	if format := strings.ToLower(strings.TrimSpace(request.Format)); format != "" && format != "csv" {
		return contract.ExportFilter{}, exportError("export_format_invalid", nil)
	}
	filters := request.Filters
	for _, value := range []*string{&filters.Event, &filters.ObjectKey, &filters.RecordID, &filters.ActorID, &filters.RoleKey, &filters.Result} {
		*value = strings.TrimSpace(*value)
		if *value != "" && !filterValue.MatchString(*value) {
			return filters, exportError("export_filter_invalid", nil)
		}
	}
	filters.Result = strings.ToLower(filters.Result)
	for _, value := range []*string{&filters.CreatedFrom, &filters.CreatedTo} {
		*value = strings.TrimSpace(*value)
		if *value != "" {
			parsed, err := time.Parse(time.RFC3339, *value)
			if err != nil {
				return filters, exportError("export_time_range_invalid", err)
			}
			*value = parsed.UTC().Format(time.RFC3339)
		}
	}
	if filters.CreatedFrom != "" && filters.CreatedTo != "" && filters.CreatedFrom > filters.CreatedTo {
		return filters, exportError("export_time_range_invalid", nil)
	}
	cutoff := now.AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	if filters.CreatedFrom == "" || filters.CreatedFrom < cutoff {
		filters.CreatedFrom = cutoff
	}
	return filters, nil
}

func ExportEventResult(event contract.Event) string {
	for _, key := range []string{"result", "outcome", "status"} {
		if value, ok := event.Metadata[key]; ok {
			result := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
			if filterValue.MatchString(result) {
				return result
			}
		}
	}
	lower := strings.ToLower(event.Event)
	for _, result := range []string{"denied", "expired", "failed", "rejected", "cancelled", "succeeded", "completed"} {
		if strings.Contains(lower, result) {
			return result
		}
	}
	return ""
}

func exportError(code string, err error) error { return &contract.ExportError{Code: code, Err: err} }
