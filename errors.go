package credbound

import "errors"

// Sentinel errors compared with errors.Is. An application HTTP adapter maps
// them to its transport error contract (for example RFC 9457 problem
// documents); the messages themselves are not part of the API.
var (
	ErrInvalidCredentials  = errors.New("credbound: invalid credentials")
	ErrUnauthorized        = errors.New("credbound: authentication required")
	ErrForbidden           = errors.New("credbound: access forbidden")
	ErrStepUpRequired      = errors.New("credbound: recent interactive AAL2 authentication required")
	ErrConflict            = errors.New("credbound: resource already exists")
	ErrNotFound            = errors.New("credbound: resource not found")
	ErrInvalidInput        = errors.New("credbound: invalid input")
	ErrExpired             = errors.New("credbound: credential expired")
	ErrLocked              = errors.New("credbound: account temporarily locked")
	ErrSSORequired         = errors.New("credbound: single sign-on required by domain policy")
	ErrDomainVerification  = errors.New("credbound: domain ownership not verified")
	ErrNoPasskey           = errors.New("credbound: user has no passkey")
	ErrAuditUnavailable    = errors.New("credbound: audit unavailable")
	ErrAuditCompromised    = errors.New("credbound: audit chain verification failed")
	ErrTransactionRejected = errors.New("credbound: transaction rejected by hook")
	ErrNotSupported        = errors.New("credbound: capability not enabled")
)

// ValidationError reports which input field failed validation and why, so a
// host can answer with structured, per-field feedback instead of parsing the
// error text. It always matches errors.Is(err, ErrInvalidInput); retrieve it
// with errors.As. User-input validation failures (addresses, passwords, names,
// roles) carry one; protocol-level rejections may still return a plain
// ErrInvalidInput.
type ValidationError struct {
	// Field names the offending input in lower_snake_case, e.g. "email",
	// "password", "display_name", "workspace_name", "role".
	Field string
	// Rule is a stable machine-readable identifier of the violated rule,
	// e.g. "required", "format", "too_short", "too_long", "unknown".
	Rule string
	// Message is a human-readable English description for logs; hosts
	// localize their own user-facing copy from Field and Rule.
	Message string
}

func (e *ValidationError) Error() string {
	return "credbound: invalid input: " + e.Field + " " + e.Rule + ": " + e.Message
}

// Unwrap makes every ValidationError satisfy errors.Is(err, ErrInvalidInput).
func (e *ValidationError) Unwrap() error { return ErrInvalidInput }
