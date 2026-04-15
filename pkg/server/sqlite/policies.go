package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// PolicyOf returns the [PubkeyPolicy] for a pubkey.
// It returns [ErrPolicyNotFound] if no policy exists for the pubkey.
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

// PubkeysAllowed returns a list of pubkeys that have an explicit "allowed" status.
func (db DB) PubkeysAllowed(ctx context.Context) ([]string, error) {
	pubkeys, err := db.pubkeysStatus(ctx, StatusAllowed)
	if err != nil {
		return nil, fmt.Errorf("failed to query for the allowed pubkeys: %w", err)
	}
	return pubkeys, nil
}

// PubkeysBlocked returns a list of pubkeys that have an explicit "blocked" status.
func (db DB) PubkeysBlocked(ctx context.Context) ([]string, error) {
	pubkeys, err := db.pubkeysStatus(ctx, StatusBlocked)
	if err != nil {
		return nil, fmt.Errorf("failed to query for the blocked pubkeys: %w", err)
	}
	return pubkeys, nil
}

func (db DB) pubkeysStatus(ctx context.Context, status PubkeyStatus) ([]string, error) {
	var pubkeys []string
	rows, err := db.conn.QueryContext(ctx, `SELECT pubkey FROM pubkey_policies WHERE status = ?`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var pubkey string
		if err := rows.Scan(&pubkey); err != nil {
			return nil, err
		}
		pubkeys = append(pubkeys, pubkey)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return pubkeys, nil
}

// IsAllowed reports whether the pubkey has an explicit "allowed" status.
func (db DB) IsAllowed(ctx context.Context, pubkey string) (bool, error) {
	status, err := db.statusOf(ctx, pubkey)
	if err != nil {
		return false, fmt.Errorf("failed to check if the pubkey is allowed: %w", err)
	}
	return status == StatusAllowed, nil
}

// IsBlocked reports whether the pubkey has an explicit "blocked" status.
func (db DB) IsBlocked(ctx context.Context, pubkey string) (bool, error) {
	status, err := db.statusOf(ctx, pubkey)
	if err != nil {
		return false, fmt.Errorf("failed to check if the pubkey is blocked: %w", err)
	}
	return status == StatusBlocked, nil
}

func (db DB) statusOf(ctx context.Context, pubkey string) (PubkeyStatus, error) {
	var s PubkeyStatus
	err := db.conn.QueryRowContext(ctx, `
		SELECT status FROM pubkey_policies WHERE pubkey = ?
	`, pubkey).Scan(&s)
	if err != nil {
		return "", err
	}
	return s, nil
}
