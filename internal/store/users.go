package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// User is a person who may sign in through an identity provider.
type User struct {
	ID          int64      `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name,omitempty"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// UserLogin is what an identity provider asserted at sign-in.
type UserLogin struct {
	Issuer      string
	Subject     string
	Email       string
	DisplayName string
	Role        string
}

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserEmailRequired    = errors.New("user email is required")
	ErrUserIdentityRequired = errors.New("user identity issuer and subject are required")
)

// NormalizeUserEmail folds an address the way the users table stores it.
func NormalizeUserEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// RecordUserLogin binds the asserted identity to a user, creating the user on
// first sight, and refreshes the display name, role, and last-login time. A
// user is found by (issuer, subject) first and by case-folded email second.
// The returned user may be disabled; callers decide what that means.
func (s *Store) RecordUserLogin(ctx context.Context, login UserLogin) (user *User, retErr error) {
	email := NormalizeUserEmail(login.Email)
	if email == "" {
		return nil, ErrUserEmailRequired
	}
	if login.Issuer == "" || login.Subject == "" {
		return nil, ErrUserIdentityRequired
	}
	tx, err := s.db.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin user login: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	logged := &loggedTx{Tx: tx, rebind: s.Rebind}
	now := s.dialect.Now()

	var userID int64
	err = logged.QueryRowContext(ctx,
		`SELECT user_id FROM user_identities WHERE issuer = ? AND subject = ?`,
		login.Issuer, login.Subject).Scan(&userID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		err = logged.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			err = logged.QueryRowContext(ctx,
				`INSERT INTO users (email, display_name, role) VALUES (?, ?, ?) RETURNING id`,
				email, login.DisplayName, login.Role).Scan(&userID)
		}
		if err != nil {
			return nil, fmt.Errorf("find or create user %q: %w", email, err)
		}
		if _, err := logged.ExecContext(ctx,
			`INSERT INTO user_identities (user_id, issuer, subject, last_login_at) VALUES (?, ?, ?, `+now+`)`,
			userID, login.Issuer, login.Subject); err != nil {
			return nil, fmt.Errorf("bind user identity: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("look up user identity: %w", err)
	default:
		if _, err := logged.ExecContext(ctx,
			`UPDATE user_identities SET last_login_at = `+now+` WHERE issuer = ? AND subject = ?`,
			login.Issuer, login.Subject); err != nil {
			return nil, fmt.Errorf("touch user identity: %w", err)
		}
		// The provider may have changed the address; follow it unless another
		// user already owns the new one.
		if _, err := logged.ExecContext(ctx,
			`UPDATE users SET email = ? WHERE id = ? AND NOT EXISTS (SELECT 1 FROM users other WHERE other.email = ? AND other.id <> ?)`,
			email, userID, email, userID); err != nil {
			return nil, fmt.Errorf("update user email: %w", err)
		}
	}
	if _, err := logged.ExecContext(ctx,
		`UPDATE users SET display_name = ?, role = ?, last_login_at = `+now+`, updated_at = `+now+` WHERE id = ?`,
		login.DisplayName, login.Role, userID); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	user, err = scanUser(logged.QueryRowContext(ctx, selectUserSQL+` WHERE id = ?`, userID))
	if err != nil {
		return nil, fmt.Errorf("reload user %d: %w", userID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit user login: %w", err)
	}
	return user, nil
}

const selectUserSQL = `SELECT id, email, display_name, role, disabled, created_at, updated_at, last_login_at FROM users`

// GetUser returns one user by ID.
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, selectUserSQL+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user %d: %w", id, err)
	}
	return user, nil
}

// ListUsers returns every user ordered by email.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, selectUserSQL+` ORDER BY email`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, *user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// SetUserDisabled blocks or restores a user's sign-in.
func (s *Store) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE users SET disabled = ?, updated_at = `+s.dialect.Now()+` WHERE id = ?`, disabled, id)
	if err != nil {
		return fmt.Errorf("set user %d disabled: %w", id, err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func scanUser(row scanner) (*User, error) {
	var (
		user      User
		lastLogin sql.NullTime
	)
	if err := row.Scan(&user.ID, &user.Email, &user.DisplayName, &user.Role, &user.Disabled,
		&user.CreatedAt, &user.UpdatedAt, &lastLogin); err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		at := lastLogin.Time
		user.LastLoginAt = &at
	}
	return &user, nil
}

// GetUserByEmail returns the user with this case-folded address.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx, selectUserSQL+` WHERE email = ?`, NormalizeUserEmail(email)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return user, nil
}

// GetUserByIdentity returns the user bound to an identity-provider account.
func (s *Store) GetUserByIdentity(ctx context.Context, issuer, subject string) (*User, error) {
	user, err := scanUser(s.db.QueryRowContext(ctx,
		selectUserSQL+` WHERE id = (SELECT user_id FROM user_identities WHERE issuer = ? AND subject = ?)`,
		issuer, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by identity: %w", err)
	}
	return user, nil
}

// ListUserSourceIDs returns the sources bound to a user, in ID order. The
// result is never nil, so an unbound user gets an empty, fail-closed scope.
func (s *Store) ListUserSourceIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source_id FROM user_sources WHERE user_id = ? ORDER BY source_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan user source: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user sources: %w", err)
	}
	return ids, nil
}

// SetUserSources replaces the sources bound to a user. Unknown source IDs
// fail the whole call so a typo cannot silently bind nothing.
func (s *Store) SetUserSources(ctx context.Context, userID int64, sourceIDs []int64) (retErr error) {
	if _, err := s.GetUser(ctx, userID); err != nil {
		return err
	}
	tx, err := s.db.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin set user sources: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	logged := &loggedTx{Tx: tx, rebind: s.Rebind}
	if _, err := logged.ExecContext(ctx, `DELETE FROM user_sources WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("clear user sources: %w", err)
	}
	for _, sourceID := range sourceIDs {
		var exists int
		if err := logged.QueryRowContext(ctx, `SELECT COUNT(*) FROM sources WHERE id = ?`, sourceID).Scan(&exists); err != nil {
			return fmt.Errorf("check source %d: %w", sourceID, err)
		}
		if exists == 0 {
			return fmt.Errorf("%w: source %d", ErrSourceNotFound, sourceID)
		}
		if _, err := logged.ExecContext(ctx,
			s.dialect.InsertOrIgnore(`INSERT OR IGNORE INTO user_sources (user_id, source_id) VALUES (?, ?)`),
			userID, sourceID); err != nil {
			return fmt.Errorf("bind source %d: %w", sourceID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user sources: %w", err)
	}
	return nil
}
