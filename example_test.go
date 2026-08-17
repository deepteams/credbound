package credbound_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
	"github.com/deepteams/credbound/memory"
	"github.com/deepteams/credbound/password"
)

// ExampleNew shows the smallest working configuration: a store, the Argon2id
// password hasher, and the three secrets. TOTP and passkey providers are
// optional — without them the related flows return ErrNotSupported while
// everything else works. Production replaces memory.New() with a SQL store
// whose migrations have been applied, and loads the secrets from a secret
// manager instead of embedding them.
func ExampleNew() {
	passwords, err := password.New(password.DefaultParams())
	if err != nil {
		log.Fatal(err)
	}
	manager, err := credbound.New(credbound.Config{
		Store:          memory.New(),
		Passwords:      passwords,
		SecretKey:      bytes.Repeat([]byte{0x11}, 32), // exactly 32 bytes
		PATPepper:      bytes.Repeat([]byte{0x22}, 32), // at least 32 bytes
		RecoveryPepper: bytes.Repeat([]byte{0x33}, 32), // at least 32 bytes
	})
	fmt.Println(manager != nil, err)
	// Output: true <nil>
}

// ExampleManager_AuthenticatePassword signs a user in with email and
// password. The deterministic clock, random source, and fast hasher come from
// the credboundtest package and are test-only.
func ExampleManager_AuthenticatePassword() {
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager, err := credbound.New(credbound.Config{
		Store:          memory.New(),
		Passwords:      credboundtest.Passwords{},
		SecretKey:      bytes.Repeat([]byte{0x11}, 32),
		PATPepper:      bytes.Repeat([]byte{0x22}, 32),
		RecoveryPepper: bytes.Repeat([]byte{0x33}, 32),
		Clock:          clock.Now,
		Random:         credboundtest.NewDeterministicRandom(),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery staple", WorkspaceName: "Main",
	}); err != nil {
		log.Fatal(err)
	}
	// The returned Authentication is a security capability: the host stores
	// it server-side and reuses it verbatim on later requests. Level 1 is
	// AAL1; only VerifyTOTP, a passkey, or SSO reauthentication produce AAL2.
	authn, err := manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery staple")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(authn.Method, authn.Level, authn.SecondFactorRequired)
	// Output: password 1 false
}

// ExampleCollectPage drains a paginated listing into one page of items plus
// the cursor for the next call. Streaming callers range over the sequence
// directly instead.
func ExampleCollectPage() {
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager, err := credbound.New(credbound.Config{
		Store:          memory.New(),
		Passwords:      credboundtest.Passwords{},
		SecretKey:      bytes.Repeat([]byte{0x11}, 32),
		PATPepper:      bytes.Repeat([]byte{0x22}, 32),
		RecoveryPepper: bytes.Repeat([]byte{0x33}, 32),
		Clock:          clock.Now,
		Random:         credboundtest.NewDeterministicRandom(),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	authn, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery staple", WorkspaceName: "Main",
	})
	if err != nil {
		log.Fatal(err)
	}
	stepUp := credboundtest.AAL2(authn.UserID, clock.Now()) // test-only step-up
	for _, name := range []string{"ci", "deploy", "backup"} {
		if _, err := manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{
			Name: name, WorkspaceID: workspace.ID, Scopes: []string{"read"},
		}); err != nil {
			log.Fatal(err)
		}
		clock.Advance(time.Second) // distinct creation instants keep the page order stable
	}
	pats, page, err := credbound.CollectPage(manager.PATs(ctx, authn, credbound.PageRequest{Limit: 2}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(pats), page.HasMore)
	rest, page, err := credbound.CollectPage(manager.PATs(ctx, authn, credbound.PageRequest{Limit: 2, Cursor: page.NextCursor}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(rest), page.HasMore)
	// Output:
	// 2 true
	// 1 false
}

// ExampleManager_CreatePAT issues a personal access token. Creation requires
// a fresh interactive AAL2 authentication (a step-up); the raw token is
// returned exactly once and only its digest is persisted.
func ExampleManager_CreatePAT() {
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager, err := credbound.New(credbound.Config{
		Store:          memory.New(),
		Passwords:      credboundtest.Passwords{},
		SecretKey:      bytes.Repeat([]byte{0x11}, 32),
		PATPepper:      bytes.Repeat([]byte{0x22}, 32),
		RecoveryPepper: bytes.Repeat([]byte{0x33}, 32),
		Clock:          clock.Now,
		Random:         credboundtest.NewDeterministicRandom(),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	authn, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery staple", WorkspaceName: "Main",
	})
	if err != nil {
		log.Fatal(err)
	}
	stepUp := credboundtest.AAL2(authn.UserID, clock.Now()) // test-only step-up
	issued, err := manager.CreatePAT(ctx, stepUp, credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(issued.PAT.Name, issued.PAT.Scopes, issued.Token != "", issued.PAT.Digest == nil)
	// Output: ci [read] true true
}
