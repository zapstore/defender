package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrPolicyNotFound = errors.New("pubkey policy not found")

type PubkeyStatus string

const (
	StatusAllowed PubkeyStatus = "allowed"
	StatusBlocked PubkeyStatus = "blocked"
)

type PubkeyPolicy struct {
	Pubkey    string
	Status    PubkeyStatus
	CreatedAt time.Time
	AddedBy   string
	Reason    string
}

// SetPolicy inserts or replaces the policy for a pubkey ("allowed" or "blocked")
func (db DB) SetPolicy(ctx context.Context, policy PubkeyPolicy) error {
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO pubkey_policies (pubkey, status, created_at, added_by, reason)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(pubkey) DO UPDATE SET
			status     = excluded.status,
			created_at = excluded.created_at,
			added_by   = excluded.added_by,
			reason     = excluded.reason
	`,
		policy.Pubkey,
		policy.Status,
		policy.CreatedAt.Unix(),
		policy.AddedBy,
		policy.Reason,
	)
	return err
}

// RemovePolicy deletes the [PubkeyPolicy] for a pubkey if it exists.
// It returns true if the policy was deleted (i.e. it existed before), false otherwise.
func (db DB) RemovePolicy(ctx context.Context, pubkey string) (bool, error) {
	res, err := db.conn.ExecContext(ctx, `DELETE FROM pubkey_policies WHERE pubkey = ?`, pubkey)
	if err != nil {
		return false, err
	}
	rowsAffected, err := res.RowsAffected()
	return rowsAffected > 0, err
}

// IsAllowed reports whether the pubkey has an explicit "allowed" status.
func (db DB) IsAllowed(ctx context.Context, pubkey string) (bool, error) {
	return db.hasStatus(ctx, pubkey, StatusAllowed)
}

// IsBlocked reports whether the pubkey has an explicit "blocked" status.
func (db DB) IsBlocked(ctx context.Context, pubkey string) (bool, error) {
	return db.hasStatus(ctx, pubkey, StatusBlocked)
}

// PolicyOf returns the [PubkeyPolicy] for a pubkey.
// It returns [ErrPubkeyPolicyNotFound] if no policy exists for the pubkey.
func (db DB) PolicyOf(ctx context.Context, pubkey string) (PubkeyPolicy, error) {
	var p PubkeyPolicy
	var createdAt int64
	err := db.conn.QueryRowContext(ctx, `
		SELECT pubkey, status, created_at, added_by, reason FROM pubkey_policies WHERE pubkey = ?
	`, pubkey).Scan(&p.Pubkey, &p.Status, &createdAt, &p.AddedBy, &p.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return PubkeyPolicy{}, ErrPolicyNotFound
	}
	if err != nil {
		return PubkeyPolicy{}, err
	}
	p.CreatedAt = time.Unix(createdAt, 0)
	return p, nil
}

func (db DB) hasStatus(ctx context.Context, pubkey string, status PubkeyStatus) (bool, error) {
	var s PubkeyStatus
	err := db.conn.QueryRowContext(ctx, `
		SELECT status FROM pubkey_policies WHERE pubkey = ?
	`, pubkey).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return s == status, nil
}
