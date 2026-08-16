package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/jackc/pgx/v5"
)

func TestValidationAndStreamingQueryFailures(t *testing.T) {
	if _, err := New(nil, nil); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("nil dependencies = %v", err)
	}
	rows := rowQuerierFunc(func(context.Context, string, ...any) (pgx.Rows, error) {
		return nil, errors.New("PostgreSQL offline")
	})
	if _, err := New(new(sql.DB), rows, WithStreamTimeout(0)); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid timeout = %v", err)
	}
	store, err := New(new(sql.DB), rows, WithStreamTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	assertPostgreSQLSequenceError(t, store.Passkeys(context.Background(), "user"))
	assertPostgreSQLSequenceError(t, store.Emails(context.Background(), "user", credbound.PageRequest{Limit: 50}))
	assertPostgreSQLSequenceError(t, store.PATs(context.Background(), "user", credbound.PageRequest{Limit: 50}))
	assertPostgreSQLSequenceError(t, store.SSOIdentities(context.Background(), "user", credbound.PageRequest{Limit: 50}))
	assertPostgreSQLSequenceError(t, store.InstanceAuditEvents(context.Background(), credbound.PageRequest{Limit: 50}))
	assertPostgreSQLSequenceError(t, store.PATs(context.Background(), "user", credbound.PageRequest{Cursor: "%%%", Limit: 50}))
}

func TestJSONBStreamScanning(t *testing.T) {
	now := time.Now().UTC()
	row := scannerFunc(func(dest ...any) error {
		*(dest[0].(*string)) = "0198b463-0000-7000-8000-000000000001"
		*(dest[1].(*string)) = "0198b463-0000-7000-8000-000000000002"
		*(dest[2].(*string)) = "Automation"
		*(dest[3].(*string)) = "prefix000001"
		*(dest[4].(*[]byte)) = []byte("digest")
		*(dest[5].(*sql.NullString)) = sql.NullString{String: "0198b463-0000-7000-8000-000000000003", Valid: true}
		*(dest[6].(*[]byte)) = []byte(`["read"]`)
		*(dest[7].(*time.Time)) = now
		*(dest[8].(*sql.NullTime)) = sql.NullTime{Time: now.Add(time.Hour), Valid: true}
		return nil
	})
	pat, err := scanPAT(row)
	if err != nil || len(pat.Scopes) != 1 || pat.Scopes[0] != "read" || pat.ExpiresAt == nil || pat.WorkspaceID == "" {
		t.Fatalf("scanned PAT = %#v, %v", pat, err)
	}
	invalid := scannerFunc(func(dest ...any) error {
		*(dest[6].(*[]byte)) = []byte("{")
		return nil
	})
	if _, err := scanPAT(invalid); err == nil {
		t.Fatal("invalid jsonb scopes accepted")
	}
	boom := errors.New("scan failed")
	if _, err := scanPAT(scannerFunc(func(...any) error { return boom })); !errors.Is(err, boom) {
		t.Fatalf("scan error = %v", err)
	}
}

type rowQuerierFunc func(context.Context, string, ...any) (pgx.Rows, error)

func (f rowQuerierFunc) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return f(ctx, query, args...)
}

type scannerFunc func(...any) error

func (f scannerFunc) Scan(values ...any) error { return f(values...) }

func assertPostgreSQLSequenceError[T any](t *testing.T, sequence func(func(T, error) bool)) {
	t.Helper()
	seen := false
	for _, err := range sequence {
		seen = true
		if err == nil {
			t.Fatal("stream yielded a nil error")
		}
	}
	if !seen {
		t.Fatal("stream did not yield an error")
	}
}
