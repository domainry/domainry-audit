package repository

import "strings"

// DataScope is the application-resolved record boundary passed explicitly to
// Audit persistence. All means that persistence must not add a range WHERE;
// otherwise the subject and organization branches are an allow union.
type DataScope struct {
	All             bool
	SubjectIDs      []string
	OrganizationIDs []string
}

func AllDataScope() DataScope { return DataScope{All: true} }

func OwnerDataScope(subjectID string) DataScope {
	return DataScope{SubjectIDs: []string{strings.TrimSpace(subjectID)}}.Normalized()
}

func (scope DataScope) Normalized() DataScope {
	if scope.All {
		return DataScope{All: true}
	}
	scope.SubjectIDs = normalizedScopeValues(scope.SubjectIDs)
	scope.OrganizationIDs = normalizedScopeValues(scope.OrganizationIDs)
	return scope
}

func normalizedScopeValues(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
