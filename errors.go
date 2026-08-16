package credbound

import "errors"

var (
	ErrInvalidCredentials  = errors.New("credbound: invalid credentials")
	ErrUnauthorized        = errors.New("credbound: authentication required")
	ErrForbidden           = errors.New("credbound: access forbidden")
	ErrStepUpRequired      = errors.New("credbound: recent interactive AAL2 authentication required")
	ErrConflict            = errors.New("credbound: resource already exists")
	ErrNotFound            = errors.New("credbound: resource not found")
	ErrInvalidInput        = errors.New("credbound: invalid input")
	ErrExpired             = errors.New("credbound: credential expired")
	ErrAuditUnavailable    = errors.New("credbound: audit unavailable")
	ErrTransactionRejected = errors.New("credbound: transaction rejected by hook")
	ErrNotSupported        = errors.New("credbound: capability not supported by store")
)
