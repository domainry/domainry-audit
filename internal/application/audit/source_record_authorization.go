package auditapp

import "github.com/domainry/domainry-foundation/apperror"

// Missing and inaccessible source records are not evidence that the viewer
// may read their audit trail. Infrastructure failures still fail the query.
func sourceRecordVisible(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	switch apperror.KindOf(err) {
	case apperror.KindForbidden, apperror.KindNotFound, apperror.KindBadRequest:
		return false, nil
	default:
		return false, err
	}
}
