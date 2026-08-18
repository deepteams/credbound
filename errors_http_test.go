package credbound_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/deepteams/credbound"
)

func TestHTTPStatusMapsEverySentinel(t *testing.T) {
	cases := map[error]int{
		nil:                                 http.StatusOK,
		credbound.ErrInvalidCredentials:     http.StatusUnauthorized,
		credbound.ErrUnauthorized:           http.StatusUnauthorized,
		credbound.ErrExpired:                http.StatusUnauthorized,
		credbound.ErrPasskeyCloneDetected:   http.StatusUnauthorized,
		credbound.ErrNoPasskey:              http.StatusUnauthorized,
		credbound.ErrForbidden:              http.StatusForbidden,
		credbound.ErrStepUpRequired:         http.StatusForbidden,
		credbound.ErrSSORequired:            http.StatusForbidden,
		credbound.ErrNotFound:               http.StatusNotFound,
		credbound.ErrConflict:               http.StatusConflict,
		credbound.ErrInvalidInput:           http.StatusBadRequest,
		credbound.ErrDomainVerification:     http.StatusUnprocessableEntity,
		credbound.ErrTransactionRejected:    http.StatusUnprocessableEntity,
		credbound.ErrLocked:                 http.StatusTooManyRequests,
		credbound.ErrNotSupported:           http.StatusNotImplemented,
		credbound.ErrAuditUnavailable:       http.StatusServiceUnavailable,
		credbound.ErrAuditCompromised:       http.StatusInternalServerError,
		errors.New("infrastructure detail"): http.StatusInternalServerError,
	}
	for err, want := range cases {
		if got := credbound.HTTPStatus(err); got != want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", err, got, want)
		}
	}
	// Wrapped sentinels and ValidationError keep their mapping.
	if got := credbound.HTTPStatus(fmt.Errorf("context: %w", credbound.ErrConflict)); got != http.StatusConflict {
		t.Errorf("wrapped sentinel = %d", got)
	}
	validation := &credbound.ValidationError{Field: "email", Rule: "format", Message: "not an address"}
	if got := credbound.HTTPStatus(validation); got != http.StatusBadRequest {
		t.Errorf("validation error = %d", got)
	}
}
