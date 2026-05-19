package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/zapstore/defender/pkg/models"
)

type AuditType string

const (
	AuditEvent AuditType = "event"
	AuditBlob  AuditType = "blob"
)

// Audit represents an audit decision recorded in the decisions table.
type Audit struct {
	Type      AuditType
	Hash      string
	Pubkey    string
	Decision  models.Decision
	Reason    string
	CheckedAt time.Time
}

// Record inserts an audit record into the decisions table.
func (db DB) Record(ctx context.Context, a Audit) error {
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO audits (type, hash, pubkey, decision, reason, checked_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		a.Type,
		a.Hash,
		a.Pubkey,
		a.Decision,
		a.Reason,
		a.CheckedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to record decision: %w", err)
	}
	return nil
}

// Audits returns the last 'limit' recorded audits.
func (db DB) Audits(ctx context.Context, limit int) ([]Audit, error) {
	query := `SELECT type, hash, pubkey, decision, reason, checked_at FROM audits
				ORDER BY checked_at DESC LIMIT ?`
	rows, err := db.conn.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var audits []Audit
	for rows.Next() {
		var a Audit
		var checkedAt int64
		err := rows.Scan(
			&a.Type,
			&a.Hash,
			&a.Pubkey,
			&a.Decision,
			&a.Reason,
			&checkedAt,
		)
		if err != nil {
			return nil, err
		}
		a.CheckedAt = time.Unix(checkedAt, 0).UTC()
		audits = append(audits, a)
	}
	return audits, nil
}
