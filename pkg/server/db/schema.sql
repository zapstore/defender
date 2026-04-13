CREATE TABLE pubkey_policies (
    pubkey TEXT PRIMARY KEY,
    status TEXT NOT NULL,        -- "allowed" | "blocked"
    created_at INTEGER NOT NULL, -- unix timestamp
    added_by TEXT,               -- "cli", "system", etc.
    reason TEXT
);

CREATE INDEX idx_pubkey_policies_status ON pubkey_policies(status);
CREATE INDEX idx_pubkey_policies_created_at ON pubkey_policies(created_at);
