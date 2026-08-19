package postgresql

import "testing"

// translate is the only place where a shared statement changes meaning between
// the two engines, so its three rules are pinned here: positional placeholders,
// schema qualification, and leaving string literals alone.
func TestTranslate(t *testing.T) {
	for name, testCase := range map[string]struct{ statement, want string }{
		"numbers placeholders in order": {
			statement: `SELECT id FROM credbound_users WHERE id = ? AND created_at < ? LIMIT ?`,
			want:      `SELECT id FROM credbound.users WHERE id = $1 AND created_at < $2 LIMIT $3`,
		},
		"qualifies every table reference": {
			statement: `SELECT u.id FROM credbound_users u JOIN credbound_user_emails e ON e.user_id = u.id AND e.is_primary`,
			want:      `SELECT u.id FROM credbound.users u JOIN credbound.user_emails e ON e.user_id = u.id AND e.is_primary`,
		},
		"keeps question marks inside string literals": {
			statement: `SELECT id FROM credbound_users WHERE display_name = 'why?' AND id = ?`,
			want:      `SELECT id FROM credbound.users WHERE display_name = 'why?' AND id = $1`,
		},
		"handles the portable cursor guard": {
			statement: `WHERE (NOT ? OR created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC LIMIT ?`,
			want:      `WHERE (NOT $1 OR created_at < $2 OR (created_at = $3 AND id < $4)) ORDER BY created_at DESC LIMIT $5`,
		},
		"leaves a statement with nothing to rewrite untouched": {
			statement: `SELECT 1`,
			want:      `SELECT 1`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := translate(testCase.statement); got != testCase.want {
				t.Fatalf("translate:\n got %s\nwant %s", got, testCase.want)
			}
		})
	}
}

// The SCIM filter fragments are concatenated into a shared builder, so they
// must survive translation as valid PostgreSQL with the placeholder numbering
// continuing from the statement they are appended to.
func TestSCIMFilterFragmentsTranslate(t *testing.T) {
	statement := `SELECT id FROM credbound_scim_users WHERE configuration_id = ?` + scimIDFilter
	if got, want := translate(statement), `SELECT id FROM credbound.scim_users WHERE configuration_id = $1 AND id::text = $2`; got != want {
		t.Fatalf("id filter:\n got %s\nwant %s", got, want)
	}
	statement = `SELECT id FROM credbound_scim_users WHERE configuration_id = ?` + scimEmailFilter
	want := `SELECT id FROM credbound.scim_users WHERE configuration_id = $1 AND EXISTS (SELECT 1 FROM jsonb_array_elements(emails_json) e WHERE e->>'value' = $2)`
	if got := translate(statement); got != want {
		t.Fatalf("email filter:\n got %s\nwant %s", got, want)
	}
}
