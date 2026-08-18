// Command minimal is a runnable, end-to-end Credbound integration: SQLite
// persistence through the pure-Go modernc.org/sqlite driver, the embedded
// migrations, Argon2id password hashing, and a net/http layer backed by
// Credbound's server-side session module (CreateSession, AuthenticateSession,
// SignOut), following the "Sessions and the Authentication capability"
// contract from the README. TOTP and passkey providers are deliberately
// omitted to show that they are optional: the related flows simply return
// ErrNotSupported.
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
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/migrations"
	"github.com/deepteams/credbound/password"
	sqlitestore "github.com/deepteams/credbound/sqlstore/sqlite"
	_ "modernc.org/sqlite"
)

func main() {
	// Secrets come from the environment as hex. When a variable is unset the
	// example generates a random development value and persists it in a
	// 0600 file next to the database, so restarts keep reading everything
	// sealed with it (PAT digests, continuations) without the secret ever
	// reaching the logs. A real deployment must provide stable secrets from
	// its secret manager and treat a missing value as fatal.
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

	// The embedded migrations must be applied before the store is used.
	// ApplySQLite is idempotent across restarts; a host already using goose
	// points it at migrations.SQLite() instead.
	if err := migrations.ApplySQLite(context.Background(), database); err != nil {
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
		// The session module persists an immutable snapshot of the
		// Authentication behind a single-display cbs_ token: the client can
		// never influence Level, Method or AuthenticatedAt, and password
		// reset, user disable, and credential revocation revoke the session
		// in the same store transaction. The cookie carries the raw token;
		// only its HMAC digest is stored.
		issued, err := manager.CreateSession(r.Context(), authn, credbound.CreateSessionInput{})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Secure is left off only because this demo serves plain HTTP on
		// loopback; production cookies are Secure and served over TLS.
		http.SetCookie(w, &http.Cookie{
			Name: "credbound_session", Value: issued.Token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("credbound_session")
		if err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		// AuthenticateSession re-validates the token digest, expiry,
		// revocation and user status on every request, and returns the
		// snapshot Authentication to use verbatim as the capability for
		// library calls; it is never rebuilt from client-supplied fields.
		authn, session, err := manager.AuthenticateSession(r.Context(), cookie.Value)
		if err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id": authn.UserID, "method": authn.Method,
			"level": authn.Level, "authenticated_at": authn.AuthenticatedAt,
			"session_id": session.ID, "session_expires_at": session.ExpiresAt,
		})
	})
	mux.HandleFunc("POST /signout", func(w http.ResponseWriter, r *http.Request) {
		// SignOut revokes by possession of the token: no step-up needed, and
		// signing out twice is a no-op. The cookie is cleared either way.
		if cookie, err := r.Cookie("credbound_session"); err == nil {
			_ = manager.SignOut(r.Context(), cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "credbound_session", Value: "", Path: "/", MaxAge: -1})
		w.WriteHeader(http.StatusNoContent)
	})

	log.Println("listening on http://127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}

// secretFromEnv reads a hex-encoded secret of exactly size bytes. When the
// variable is unset it falls back to a development value persisted in a
// 0600 file next to the database, generated on first use. The secret value
// itself is never logged: log output routinely outlives the process in
// aggregators, and a leaked SecretKey unseals every continuation.
func secretFromEnv(name string, size int) []byte {
	if encoded := os.Getenv(name); encoded != "" {
		value, err := hex.DecodeString(encoded)
		if err != nil || len(value) != size {
			log.Fatalf("%s must be %d hex-encoded bytes", name, size)
		}
		return value
	}
	path := "credbound-minimal." + strings.ToLower(name) + ".secret"
	if encoded, err := os.ReadFile(path); err == nil {
		value, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
		if err != nil || len(value) != size {
			log.Fatalf("%s holds an invalid development secret; delete the file or set %s", path, name)
		}
		return value
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		log.Fatalf("generate %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(value)+"\n"), 0o600); err != nil {
		log.Fatalf("persist development %s: %v", name, err)
	}
	log.Printf("warning: %s is unset; generated a development value in %s", name, path)
	return value
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
