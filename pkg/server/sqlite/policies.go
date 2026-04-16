package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zapstore/defender/pkg/models"
)

var ErrPolicyNotFound = errors.New("policy not found")

// SetPolicy inserts or replaces the policy for an entity ("allowed" or "blocked")
func (db DB) SetPolicy(ctx context.Context, policy models.Policy) error {
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO policies (id, platform, status, created_at, added_by, reason)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(platform, id) DO UPDATE SET
			status     = excluded.status,
			created_at = excluded.created_at,
			added_by   = excluded.added_by,
			reason     = excluded.reason
	`,
		policy.Entity.ID,
		policy.Entity.Platform,
		policy.Status,
		policy.CreatedAt.Unix(),
		policy.AddedBy,
		policy.Reason,
	)
	return err
}

// PolicyOf returns the [models.Policy] for an entity.
// It returns [ErrPolicyNotFound] if no policy exists for the entity.
func (db DB) PolicyOf(ctx context.Context, entity models.Entity) (models.Policy, error) {
	var p models.Policy
	var createdAt int64
	err := db.conn.QueryRowContext(ctx, `
		SELECT id, platform, status, created_at, added_by, reason FROM policies WHERE id = ? AND platform = ?
	`, entity.ID, entity.Platform).Scan(&p.Entity.ID, &p.Entity.Platform, &p.Status, &createdAt, &p.AddedBy, &p.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return models.Policy{}, ErrPolicyNotFound
	}
	if err != nil {
		return models.Policy{}, err
	}
	p.CreatedAt = time.Unix(createdAt, 0)
	return p, nil
}

// Policies returns all [models.Policy] entries.
// If platform is non-empty, only entries for that platform are returned.
// If status is non-empty, only entries with that status are returned.
func (db DB) Policies(ctx context.Context, platform models.Platform, status models.PolicyStatus) ([]models.Policy, error) {
	var conds []string
	var args []any
	if platform != "" {
		conds = append(conds, "platform = ?")
		args = append(args, platform)
	}
	if status != "" {
		conds = append(conds, "status = ?")
		args = append(args, status)
	}
	query := `SELECT id, platform, status, created_at, added_by, reason FROM policies`
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}

	rows, err := db.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var p models.Policy
		var createdAt int64
		err := rows.Scan(
			&p.Entity.ID,
			&p.Entity.Platform,
			&p.Status,
			&createdAt,
			&p.AddedBy,
			&p.Reason)
		if err != nil {
			return nil, err
		}
		p.CreatedAt = time.Unix(createdAt, 0).UTC()
		policies = append(policies, p)
	}
	return policies, nil
}

// DeletePolicy deletes the [models.Policy] for an entity if it exists.
// It returns true if the policy was deleted (i.e. it existed before), false otherwise.
func (db DB) DeletePolicy(ctx context.Context, entity models.Entity) (bool, error) {
	res, err := db.conn.ExecContext(ctx, `DELETE FROM policies WHERE id = ? AND platform = ?`, entity.ID, entity.Platform)
	if err != nil {
		return false, err
	}
	rowsAffected, err := res.RowsAffected()
	return rowsAffected > 0, err
}

// IsAllowed reports whether the entity has an explicit "allowed" status.
func (db DB) IsAllowed(ctx context.Context, entity models.Entity) (bool, error) {
	status, err := db.statusOf(ctx, entity)
	if err != nil {
		return false, fmt.Errorf("failed to check if the entity is allowed: %w", err)
	}
	return status == models.StatusAllowed, nil
}

// IsBlocked reports whether the entity has an explicit "blocked" status.
func (db DB) IsBlocked(ctx context.Context, entity models.Entity) (bool, error) {
	status, err := db.statusOf(ctx, entity)
	if err != nil {
		return false, fmt.Errorf("failed to check if the entity is blocked: %w", err)
	}
	return status == models.StatusBlocked, nil
}

func (db DB) statusOf(ctx context.Context, entity models.Entity) (models.PolicyStatus, error) {
	var s models.PolicyStatus
	err := db.conn.QueryRowContext(ctx, `
		SELECT status FROM policies WHERE id = ? AND platform = ?
	`, entity.ID, entity.Platform).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return s, nil
}
