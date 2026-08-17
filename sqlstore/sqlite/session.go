package sqlite

import (
	"context"
	"database/sql"
	"iter"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/sqlite"
)

// CreateSession stores a server-side session; a duplicate ID reports
// credbound.ErrConflict.
func (s *Store) CreateSession(ctx context.Context, session credbound.Session, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetUserByID(ctx, session.UserID); err != nil {
			return mapError(err)
		}
		return mapError(q.InsertSession(ctx, db.InsertSessionParams{
			ID: session.ID, UserID: session.UserID, Method: string(session.Method), Level: int64(session.Level),
			AuthenticatedAt: session.AuthenticatedAt, SecondFactorRequired: boolValue(session.SecondFactorRequired),
			UserAgent: session.UserAgent, IpAddress: session.IPAddress, Digest: session.Digest,
			CreatedAt: session.CreatedAt, LastSeenAt: session.LastSeenAt, ExpiresAt: session.ExpiresAt,
		}))
	})
}

// SessionByID returns the session with the given ID.
func (s *Store) SessionByID(ctx context.Context, id string) (credbound.Session, error) {
	row, err := s.queries.GetSession(ctx, id)
	if err != nil {
		return credbound.Session{}, mapError(err)
	}
	return sessionFromRow(row), nil
}

// TouchSession updates the session's and user's last-seen times.
func (s *Store) TouchSession(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		session, err := q.GetSession(ctx, id)
		if err != nil {
			return mapError(err)
		}
		count, err := q.TouchSession(ctx, db.TouchSessionParams{ID: id, LastSeenAt: at})
		if err := affected(count, err); err != nil {
			return err
		}
		count, err = q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: session.UserID, LastSeenAt: nullableTime(&at)})
		return affected(count, err)
	})
}

// RevokeSession marks the session revoked; an already-revoked session is
// left unchanged.
func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetSession(ctx, id); err != nil {
			return mapError(err)
		}
		// Re-revoking an already revoked session is a no-op, not an error.
		_, err := q.RevokeSessionByID(ctx, db.RevokeSessionByIDParams{ID: id, RevokedAt: nullableTime(&at)})
		return mapError(err)
	})
}

// RevokeUserSessions revokes every session of the user.
func (s *Store) RevokeUserSessions(ctx context.Context, userID string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetUserByID(ctx, userID); err != nil {
			return mapError(err)
		}
		return mapError(q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: userID, RevokedAt: nullableTime(&at)}))
	})
}

// Sessions streams the user's sessions, newest first, as one cursor page
// with digests omitted.
func (s *Store) Sessions(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Session], error] {
	return func(yield func(credbound.PageEvent[credbound.Session], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.Session]{}, err)
			return
		}
		// The digest is deliberately not selected: listings never expose it.
		rows, err := s.db.QueryContext(streamCtx, `SELECT id, user_id, method, level, authenticated_at, second_factor_required, user_agent, ip_address, created_at, last_seen_at, expires_at, revoked_at
FROM credbound_sessions
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.Session]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.Session
		count := 0
		for rows.Next() {
			value, err := scanSession(rows)
			if err != nil {
				yield(credbound.PageEvent[credbound.Session]{}, err)
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.Session](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last = value
			count++
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.Session]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.Session](credbound.PageEnd{}), nil)
	}
}

func sessionFromRow(row db.CredboundSession) credbound.Session {
	return credbound.Session{
		ID: row.ID, UserID: row.UserID, Method: credbound.AuthMethod(row.Method), Level: credbound.AssuranceLevel(row.Level),
		AuthenticatedAt: row.AuthenticatedAt, SecondFactorRequired: row.SecondFactorRequired == 1,
		UserAgent: row.UserAgent, IPAddress: row.IpAddress, Digest: row.Digest,
		CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt, ExpiresAt: row.ExpiresAt, RevokedAt: timePointer(row.RevokedAt),
	}
}

func scanSession(row scanner) (credbound.Session, error) {
	var value credbound.Session
	var method string
	var level int64
	var secondFactor int64
	var revoked sql.NullTime
	if err := row.Scan(&value.ID, &value.UserID, &method, &level, &value.AuthenticatedAt, &secondFactor, &value.UserAgent, &value.IPAddress, &value.CreatedAt, &value.LastSeenAt, &value.ExpiresAt, &revoked); err != nil {
		return credbound.Session{}, err
	}
	value.Method, value.Level = credbound.AuthMethod(method), credbound.AssuranceLevel(level)
	value.SecondFactorRequired = secondFactor == 1
	value.RevokedAt = timePointer(revoked)
	return value, nil
}

var _ credbound.SessionStore = (*Store)(nil)
