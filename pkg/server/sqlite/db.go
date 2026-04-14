// Package sqlite provides a sqlite-backed store for the defender server.
package sqlite

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schema string

type DB struct {
	conn *sql.DB
}

// New creates a new store with the given path.
func New(c Config) (DB, error) {
	db, err := sql.Open("sqlite3", c.Path)
	if err != nil {
		return DB{}, fmt.Errorf("failed to connect to sqlite3 at %s: %w", c.Path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		return DB{}, fmt.Errorf("failed to apply base schema: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL;"); err != nil {
		return DB{}, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
		return DB{}, fmt.Errorf("failed to set busy timeout: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return DB{}, fmt.Errorf("failed to activate foreign keys: %w", err)
	}
	if _, err = db.Exec("PRAGMA optimize=0x10002;"); err != nil {
		return DB{}, fmt.Errorf("failed to PRAGMA optimize: %w", err)
	}
	return DB{conn: db}, nil
}

func (db DB) Close() error {
	return db.conn.Close()
}
