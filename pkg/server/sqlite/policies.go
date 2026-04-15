package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/zapstore/defender/pkg/models"
)

var ErrPolicyNotFound = errors.New("pubkey policy not found")

// SetPolicy inserts or replaces the policy for a pubkey ("allowed" or "blocked")
func (db DB) SetPolicy(ctx context.Context, policy models.PubkeyPolicy) error {
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

// PolicyOf returns the [models.PubkeyPolicy] for a pubkey.
// It returns [ErrPolicyNotFound] if no policy exists for the pubkey.
func (db DB) PolicyOf(ctx context.Context, pubkey string) (models.PubkeyPolicy, error) {
	var p models.PubkeyPolicy
	var createdAt int64
	err := db.conn.QueryRowContext(ctx, `
		SELECT pubkey, status, created_at, added_by, reason FROM pubkey_policies WHERE pubkey = ?
	`, pubkey).Scan(&p.Pubkey, &p.Status, &createdAt, &p.AddedBy, &p.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return models.PubkeyPolicy{}, ErrPolicyNotFound
	}
	if err != nil {
		return models.PubkeyPolicy{}, err
	}
	p.CreatedAt = time.Unix(createdAt, 0)
	return p, nil
}

// Policies returns all [models.PubkeyPolicy] entries.
// If status is non-empty, only entries with that status are returned.
func (db DB) Policies(ctx context.Context, status models.PubkeyStatus) ([]models.PubkeyPolicy, error) {
	query := `SELECT pubkey, status, created_at, added_by, reason FROM pubkey_policies `
	var args []any
	if status != "" {
		query += `WHERE status = ?`
		args = append(args, status)
	}

	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.PubkeyPolicy
	for rows.Next() {
		var p models.PubkeyPolicy
		var createdAt int64
		if err := rows.Scan(&p.Pubkey, &p.Status, &createdAt, &p.AddedBy, &p.Reason); err != nil {
			return nil, err
		}
		p.CreatedAt = time.Unix(createdAt, 0)
		policies = append(policies, p)
	}
	return policies, nil
}

// RemovePolicy deletes the [models.PubkeyPolicy] for a pubkey if it exists.
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
	status, err := db.statusOf(ctx, pubkey)
	if err != nil {
		return false, fmt.Errorf("failed to check if the pubkey is allowed: %w", err)
	}
	return status == models.StatusAllowed, nil
}

// IsBlocked reports whether the pubkey has an explicit "blocked" status.
func (db DB) IsBlocked(ctx context.Context, pubkey string) (bool, error) {
	status, err := db.statusOf(ctx, pubkey)
	if err != nil {
		return false, fmt.Errorf("failed to check if the pubkey is blocked: %w", err)
	}
	return status == models.StatusBlocked, nil
}

func (db DB) statusOf(ctx context.Context, pubkey string) (models.PubkeyStatus, error) {
	var s models.PubkeyStatus
	err := db.conn.QueryRowContext(ctx, `
		SELECT status FROM pubkey_policies WHERE pubkey = ?
	`, pubkey).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return s, nil
}
