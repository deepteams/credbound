package credbound

import (
	"errors"
	"net/http"
)

// HTTPStatus maps an error returned by any Manager operation to the HTTP
// status code a host transport would conventionally answer with, so every
// integrator does not re-write the same errors.Is ladder. nil maps to 200 and
// an unrecognized error to 500, so infrastructure failures never leak detail.
//
// The mapping is intentionally coarse — a body format such as an RFC 9457
// problem document, localized copy, and headers like Retry-After or
// WWW-Authenticate remain the host's contract. Hosts needing a different
// convention (401 versus 403 for step-up, 423 versus 429 for lockout) keep
// writing their own switch; this helper is the documented default:
//
//	401 ErrInvalidCredentials, ErrUnauthorized, ErrExpired,
//	    ErrPasskeyCloneDetected, ErrNoPasskey (folded with invalid
//	    credentials so passkey presence never leaks)
//	403 ErrForbidden, ErrStepUpRequired, ErrSSORequired
//	404 ErrNotFound
//	409 ErrConflict
//	400 ErrInvalidInput (including every ValidationError)
//	422 ErrDomainVerification, ErrTransactionRejected
//	429 ErrLocked
//	501 ErrNotSupported
//	503 ErrAuditUnavailable
//	500 ErrAuditCompromised and anything unrecognized
func HTTPStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrExpired), errors.Is(err, ErrPasskeyCloneDetected),
		errors.Is(err, ErrNoPasskey):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrStepUpRequired), errors.Is(err, ErrSSORequired):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, ErrDomainVerification), errors.Is(err, ErrTransactionRejected):
		return http.StatusUnprocessableEntity
	case errors.Is(err, ErrLocked):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrNotSupported):
		return http.StatusNotImplemented
	case errors.Is(err, ErrAuditUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
