// Command minimal is a runnable, end-to-end Credbound integration: SQLite
// persistence through the pure-Go modernc.org/sqlite driver, the embedded
// migrations, Argon2id password hashing, and a net/http session layer that
// follows the "Sessions and the Authentication capability" contract from the
// README. TOTP and passkey providers are deliberately omitted to show that
// they are optional: the related flows simply return ErrNotSupported.
//
//	go run ./examples/minimal
//	curl -c jar -X POST -d 'email=root@example.com' --data-urlencode 'password=correct horse battery staple' http://127.0.0.1:8080/signin
//	curl -b jar http://127.0.0.1:8080/me
//	curl -b jar -X POST http://127.0.0.1:8080/signout
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/migrations"
	"github.com/deepteams/credbound/password"
	sqlitestore "github.com/deepteams/credbound/sqlstore/sqlite"
	_ "modernc.org/sqlite"
)

func main() {
	// Secrets come from the environment as hex. When a variable is unset the
	// example generates a random development value and warns: everything
	// sealed with it (PAT digests, continuations) becomes unreadable on the
	// next start. A real deployment must provide stable secrets from its
	// secret manager and treat a missing value as fatal.
	secretKey := secretFromEnv("CREDBOUND_SECRET_KEY", 32)
	patPepper := secretFromEnv("CREDBOUND_PAT_PEPPER", 32)
	recoveryPepper := secretFromEnv("CREDBOUND_RECOVERY_PEPPER", 32)

	// foreign_keys enforces the schema's referential integrity and
	// _texttotime makes the driver scan DATETIME columns into time.Time, both
	// of which the SQLite store relies on.
	dsn := os.Getenv("CREDBOUND_SQLITE_DSN")
	if dsn == "" {
		dsn = "file:credbound-minimal.db?_pragma=foreign_keys(1)&_texttotime=1"
	}
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer database.Close()

	// The embedded migrations must be applied before the store is used. Their
	// filenames are goose timestamps, so lexical order is application order; a
	// host already using goose points it at migrations.SQLite() instead of
	// reimplementing this loop.
	if err := applyMigrations(database); err != nil {
		log.Fatalf("apply migrations: %v", err)
	}

	store, err := sqlitestore.New(database)
	if err != nil {
		log.Fatalf("build store: %v", err)
	}
	// Argon2id with the library defaults is the production password hasher.
	passwords, err := password.New(password.DefaultParams())
	if err != nil {
		log.Fatalf("build password hasher: %v", err)
	}
	// TOTP and Passkeys are omitted: both providers are optional and their
	// flows return credbound.ErrNotSupported until the host wires
	// totpadapter/webauthnadapter.
	manager, err := credbound.New(credbound.Config{
		Store:          store,
		Passwords:      passwords,
		SecretKey:      secretKey,      // exactly 32 bytes
		PATPepper:      patPepper,      // at least 32 bytes
		RecoveryPepper: recoveryPepper, // at least 32 bytes
	})
	if err != nil {
		log.Fatalf("build manager: %v", err)
	}

	// The first run creates the root user, their workspace, their admin
	// membership and their instance-level root role atomically. Every later
	// run hits ErrConflict, which simply means the instance already exists.
	bootstrap(manager)

	// The host owns sessions. This example keeps each Authentication
	// server-side in a map keyed by a random 128-bit identifier and hands the
	// browser only that identifier, so the client can never influence Level,
	// Method or AuthenticatedAt. Sessions die with the process; a real host
	// persists them (or uses a signed and encrypted cookie) and terminates
	// them on password reset, user disable, or credential revocation.
	sessions := &sessionStore{authns: make(map[string]credbound.Authentication)}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /signin", func(w http.ResponseWriter, r *http.Request) {
		authn, err := manager.AuthenticatePassword(r.Context(), r.FormValue("email"), r.FormValue("password"))
		switch {
		case errors.Is(err, credbound.ErrInvalidCredentials), errors.Is(err, credbound.ErrLocked):
			// One answer for unknown address, wrong password and locked
			// account: the library is enumeration-resistant, the host should
			// not undo that in its responses.
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		case err != nil:
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		case authn.SecondFactorRequired:
			// A pending session must stay out of authorized paths until
			// VerifyTOTP returns the AAL2 Authentication to store instead.
			// This example wires no TOTP provider, so it stops here.
			http.Error(w, "second factor required", http.StatusForbidden)
			return
		}
		id, err := sessions.create(authn)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Secure is left off only because this demo serves plain HTTP on
		// loopback; production cookies are Secure and served over TLS.
		http.SetCookie(w, &http.Cookie{
			Name: "credbound_session", Value: id, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		authn, ok := sessions.get(r)
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		// The stored Authentication is reused verbatim as the capability for
		// library calls; it is never rebuilt from client-supplied fields.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id": authn.UserID, "method": authn.Method,
			"level": authn.Level, "authenticated_at": authn.AuthenticatedAt,
		})
	})
	mux.HandleFunc("POST /signout", func(w http.ResponseWriter, r *http.Request) {
		sessions.remove(r)
		http.SetCookie(w, &http.Cookie{Name: "credbound_session", Value: "", Path: "/", MaxAge: -1})
		w.WriteHeader(http.StatusNoContent)
	})

	log.Println("listening on http://127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}

// secretFromEnv reads a hex-encoded secret of exactly size bytes, generating
// a random development value with a warning when the variable is unset.
func secretFromEnv(name string, size int) []byte {
	if encoded := os.Getenv(name); encoded != "" {
		value, err := hex.DecodeString(encoded)
		if err != nil || len(value) != size {
			log.Fatalf("%s must be %d hex-encoded bytes", name, size)
		}
		return value
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		log.Fatalf("generate %s: %v", name, err)
	}
	log.Printf("warning: %s is unset; using a random development value, e.g. %s=%s", name, name, hex.EncodeToString(value))
	return value
}

// applyMigrations executes the Up section of every embedded SQLite migration
// in filename order, remembering applied files in a bookkeeping table so
// restarts are idempotent. Production hosts typically hand migrations.SQLite()
// to goose, whose version table serves the same purpose.
func applyMigrations(database *sql.DB) error {
	if _, err := database.Exec(`CREATE TABLE IF NOT EXISTS example_migrations (filename TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	migrationFS := migrations.SQLite()
	entries, err := fs.ReadDir(migrationFS, ".") // sorted by filename
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var applied int
		if err := database.QueryRow(`SELECT COUNT(*) FROM example_migrations WHERE filename = ?`, entry.Name()).Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		migration, err := fs.ReadFile(migrationFS, entry.Name())
		if err != nil {
			return err
		}
		up, _, _ := strings.Cut(string(migration), "-- +goose Down")
		if _, err := database.Exec(up); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if _, err := database.Exec(`INSERT INTO example_migrations (filename) VALUES (?)`, entry.Name()); err != nil {
			return err
		}
		log.Printf("applied migration %s", entry.Name())
	}
	return nil
}

// bootstrap creates the first user and workspace once and tolerates every
// later run. Override the identity with CREDBOUND_BOOTSTRAP_EMAIL and
// CREDBOUND_BOOTSTRAP_PASSWORD; change the default password immediately in
// anything resembling a real deployment.
func bootstrap(manager *credbound.Manager) {
	email := os.Getenv("CREDBOUND_BOOTSTRAP_EMAIL")
	if email == "" {
		email = "root@example.com"
	}
	pass := os.Getenv("CREDBOUND_BOOTSTRAP_PASSWORD")
	if pass == "" {
		pass = "correct horse battery staple"
		log.Printf("warning: CREDBOUND_BOOTSTRAP_PASSWORD is unset; using the documented demo password")
	}
	_, workspace, err := manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: email, DisplayName: "Root", Password: pass, WorkspaceName: "Main",
	})
	switch {
	case errors.Is(err, credbound.ErrConflict):
		log.Println("instance already bootstrapped")
	case err != nil:
		log.Fatalf("bootstrap: %v", err)
	default:
		log.Printf("bootstrapped %s in workspace %q", email, workspace.Name)
	}
}

// sessionStore is the minimal host-side session table: random identifier to
// server-side Authentication.
type sessionStore struct {
	mu     sync.Mutex
	authns map[string]credbound.Authentication
}

func (s *sessionStore) create(authn credbound.Authentication) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authns[id] = authn
	return id, nil
}

func (s *sessionStore) get(r *http.Request) (credbound.Authentication, bool) {
	cookie, err := r.Cookie("credbound_session")
	if err != nil {
		return credbound.Authentication{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	authn, ok := s.authns[cookie.Value]
	return authn, ok
}

func (s *sessionStore) remove(r *http.Request) {
	cookie, err := r.Cookie("credbound_session")
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.authns, cookie.Value)
}
