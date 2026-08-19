package postgresql

import (
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

// The statements assembled in Go number their own parameters, which is the one
// thing in this package a compiler cannot check: a clause added without
// bumping the counter, or an argument appended in the wrong order, produces a
// statement that only fails against a live server. These tests pin, for every
// shape each builder can produce, that the placeholders run 1..N with no gap
// and that exactly N arguments come back.

var placeholder = regexp.MustCompile(`\$(\d+)`)

// assertNumbering fails unless the statement's highest placeholder equals the
// argument count and every number in between appears.
func assertNumbering(t *testing.T, query string, args []any) {
	t.Helper()
	seen := map[int]bool{}
	highest := 0
	for _, match := range placeholder.FindAllStringSubmatch(query, -1) {
		number, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatalf("unparsable placeholder %q in:\n%s", match[1], query)
		}
		seen[number] = true
		highest = max(highest, number)
	}
	if highest != len(args) {
		t.Fatalf("highest placeholder $%d but %d argument(s):\n%s", highest, len(args), query)
	}
	for number := 1; number <= highest; number++ {
		if !seen[number] {
			t.Fatalf("$%d is never referenced:\n%s", number, query)
		}
	}
}

func TestWorkspacesQueryNumbering(t *testing.T) {
	after := cursor{Time: time.Now(), ID: credbound.MustParseUUID("018f0000-0000-7000-8000-000000000001")}
	for name, testCase := range map[string]struct {
		userID credbound.UUID
		cursor cursor
	}{
		"no filter, first page":   {credbound.UUID{}, cursor{}},
		"no filter, resumed":      {credbound.UUID{}, after},
		"user filter, first page": {credbound.MustParseUUID("018f0000-0000-7000-8000-000000000002"), cursor{}},
		"user filter, resumed":    {credbound.MustParseUUID("018f0000-0000-7000-8000-000000000002"), after},
	} {
		t.Run(name, func(t *testing.T) {
			query, args := workspacesQuery(testCase.userID, testCase.cursor, 51)
			assertNumbering(t, query, args)
		})
	}
}

func TestAuditEventsQueryNumbering(t *testing.T) {
	after := cursor{Time: time.Now(), ID: credbound.MustParseUUID("018f0000-0000-7000-8000-000000000001")}
	for name, testCase := range map[string]struct {
		workspaceID credbound.UUID
		cursor      cursor
	}{
		"instance-wide, first page": {credbound.UUID{}, cursor{}},
		"instance-wide, resumed":    {credbound.UUID{}, after},
		"workspace, first page":     {credbound.MustParseUUID("018f0000-0000-7000-8000-000000000002"), cursor{}},
		"workspace, resumed":        {credbound.MustParseUUID("018f0000-0000-7000-8000-000000000002"), after},
	} {
		t.Run(name, func(t *testing.T) {
			query, args := auditEventsQuery(testCase.workspaceID, testCase.cursor, 51)
			assertNumbering(t, query, args)
		})
	}
}

func TestSCIMListQueryNumbering(t *testing.T) {
	var configurationID = credbound.MustParseUUID("018f0000-0000-7000-8000-000000000002")
	after := cursor{Time: time.Now(), ID: credbound.MustParseUUID("018f0000-0000-7000-8000-000000000001")}
	userFilters := []credbound.SCIMFilter{
		{},
		{Attribute: "id", Value: configurationID.String()},
		{Attribute: "externalId", Value: "ext-1"},
		{Attribute: "userName", Value: "Someone"},
		{Attribute: "emails.value", Value: "someone@example.test"},
		{Attribute: "active", Value: "true"},
	}
	for _, filter := range userFilters {
		for _, page := range []cursor{{}, after} {
			query, args, err := scimUserListQuery(configurationID, filter, page, 51)
			if err != nil {
				t.Fatalf("user filter %q: %v", filter.Attribute, err)
			}
			assertNumbering(t, query, args)
		}
	}
	groupFilters := []credbound.SCIMFilter{
		{},
		{Attribute: "id", Value: configurationID.String()},
		{Attribute: "externalId", Value: "ext-1"},
		{Attribute: "displayName", Value: "Engineering"},
	}
	for _, filter := range groupFilters {
		for _, page := range []cursor{{}, after} {
			query, args, err := scimGroupListQuery(configurationID, filter, page, 51)
			if err != nil {
				t.Fatalf("group filter %q: %v", filter.Attribute, err)
			}
			assertNumbering(t, query, args)
		}
	}
}

// An unsupported filter attribute must be refused rather than silently
// widening the listing to every row the credential can reach.
func TestSCIMListQueryRejectsUnknownFilters(t *testing.T) {
	var configurationID = credbound.MustParseUUID("018f0000-0000-7000-8000-000000000002")
	if _, _, err := scimUserListQuery(configurationID, credbound.SCIMFilter{Attribute: "password"}, cursor{}, 51); err == nil {
		t.Fatal("unsupported user filter accepted")
	}
	if _, _, err := scimUserListQuery(configurationID, credbound.SCIMFilter{Attribute: "active", Value: "perhaps"}, cursor{}, 51); err == nil {
		t.Fatal("non-boolean active filter accepted")
	}
	if _, _, err := scimGroupListQuery(configurationID, credbound.SCIMFilter{Attribute: "members"}, cursor{}, 51); err == nil {
		t.Fatal("unsupported group filter accepted")
	}
}

// The keyset statements come in a first-page and a resumed form. The resumed
// one must carry the cursor comparison as a row constructor, and the first-page
// one must not carry it at all: a guard in the first-page statement, or an
// OR-spelled comparison in the resumed one, costs the ordered index scan.
func TestKeysetStatementsPairUp(t *testing.T) {
	for name, pair := range map[string][2]string{
		"users":            {usersFirstPage, usersAfterCursor},
		"emails":           {emailsFirstPage, emailsAfterCursor},
		"pats":             {patsFirstPage, patsAfterCursor},
		"invitations":      {invitationsFirstPage, invitationsAfterCursor},
		"memberships":      {membershipsFirstPage, membershipsAfterCursor},
		"ssoIdentities":    {ssoIdentitiesFirstPage, ssoIdentitiesAfterCursor},
		"workspaceDomains": {workspaceDomainsFirstPage, workspaceDomainsAfterCursor},
		"sessions":         {sessionsFirstPage, sessionsAfterCursor},
	} {
		t.Run(name, func(t *testing.T) {
			first, resumed := pair[0], pair[1]
			rowComparison := regexp.MustCompile(`\((created_at|u\.created_at), (id|user_id|u\.id)\) < \(`)
			if rowComparison.MatchString(first) {
				t.Fatalf("the first page carries a cursor comparison:\n%s", first)
			}
			if !rowComparison.MatchString(resumed) {
				t.Fatalf("the resumed page has no row-constructor cursor comparison:\n%s", resumed)
			}
			for _, statement := range pair {
				if regexp.MustCompile(`\bNOT \$`).MatchString(statement) {
					t.Fatalf("a boolean guard survived:\n%s", statement)
				}
				if regexp.MustCompile(`created_at = \$`).MatchString(statement) {
					t.Fatalf("the cursor comparison was spelled with OR, which loses the ordered index scan:\n%s", statement)
				}
			}
		})
	}
}

// A caller-supplied identifier that is not a UUID must produce an empty page
// rather than failing the listing, and must never reach the uuid comparison.
func TestSCIMIDFilterRejectsMalformedUUID(t *testing.T) {
	var configurationID = credbound.MustParseUUID("018f0000-0000-7000-8000-000000000002")
	for _, value := range []string{"not-a-uuid", "", "018f0000-0000-7000-8000-00000000000", "018f0000_0000_7000_8000_000000000001", "018f0000-0000-7000-8000-00000000000g"} {
		query, args, err := scimUserListQuery(configurationID, credbound.SCIMFilter{Attribute: "id", Value: value}, cursor{}, 51)
		if err != nil {
			t.Fatalf("%q = %v", value, err)
		}
		if !regexp.MustCompile(`AND false`).MatchString(query) {
			t.Fatalf("%q was not short-circuited:\n%s", value, query)
		}
		assertNumbering(t, query, args)
	}
	if !validUUID("018f0000-0000-7000-8000-000000000001") || !validUUID("018F0000-0000-7000-8000-00000000000A") {
		t.Fatal("a well-formed UUID was rejected")
	}
}
