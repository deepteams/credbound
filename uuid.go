package credbound

import (
	"fmt"

	"github.com/deepteams/credbound/internal/uuid"
)

// UUID identifies every Credbound record: the 16 raw bytes PostgreSQL stores in
// a uuid column. It is comparable, so it works with == and as a map key, and it
// costs 16 bytes rather than the 36 of the canonical text.
//
// Every identifier the library mints is a UUIDv7 (RFC 9562), so identifiers
// sort by creation time — which is what cursor pagination and the audit
// ordering rely on.
//
// The zero value means "no identifier": it is what an absent optional
// reference reads as, and it maps to SQL NULL in both directions. A zero UUID
// carries neither version 7 nor the RFC variant, so it never passes the checks
// at the API boundary nor the CHECK constraints in the schema.
//
// This is an alias, not a new type, so it stays interchangeable with the
// package it comes from. That package is the one accepted for the Go standard
// library (golang/go#62026), vendored verbatim under internal/uuid until it
// ships; when it does, this alias is repointed at the standard library and the
// vendored copy is deleted, with no other change. Nothing depends on methods
// the standard library does not provide: the store binds pgtype.UUID for its
// rows and converts at the boundary.
type UUID = uuid.UUID

// ParseUUID reads an identifier in its canonical 8-4-4-4-12 form. A malformed
// value reports ErrInvalidInput, so a caller can classify it like any other
// rejected input.
//
// Only the canonical form is accepted. The underlying parser also takes the
// compact, braced and urn:uuid: spellings, but Credbound does not: those would
// give one record several spellings that String never renders back, so a client
// comparing or caching what it received would see identifiers that differ from
// the ones the library returns.
func ParseUUID(value string) (UUID, error) {
	reject := func() (UUID, error) {
		return UUID{}, fmt.Errorf("%w: %q is not a UUID", ErrInvalidInput, value)
	}
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return reject()
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return reject()
	}
	return id, nil
}

// MustParseUUID is ParseUUID for constants and tests; it panics on a malformed
// value and must never be handed anything a caller supplied.
func MustParseUUID(value string) UUID {
	id, err := ParseUUID(value)
	if err != nil {
		panic(err)
	}
	return id
}

// validUUIDv7 reports whether the identifier was minted by Credbound: present,
// version 7, and carrying the RFC 9562 variant. The format itself can no longer
// be wrong — a UUID is sixteen bytes — so this is the whole of the check the
// string-based predicate used to perform.
func validUUIDv7(id UUID) bool {
	return id[6]&0xf0 == 0x70 && id[8]&0xc0 == 0x80
}
