CREATE TABLE IF NOT EXISTS policies (
    id         TEXT NOT NULL,    -- the platform specific identifier. If nostr, this is the pubkey.
    platform   TEXT NOT NULL,    -- "nostr", "github", "gitlab", "codeberg" etc.
    status TEXT NOT NULL,        -- "allowed" | "blocked"
    created_at INTEGER NOT NULL, -- unix timestamp
    added_by TEXT,               -- "cli", "system", etc.
    reason TEXT,

    PRIMARY KEY (platform, id)
);

CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_policies_platform ON policies(platform);
CREATE INDEX IF NOT EXISTS idx_policies_platform_status ON policies(platform, status);
CREATE INDEX IF NOT EXISTS idx_policies_created_at ON policies(created_at);

CREATE TABLE IF NOT EXISTS audits (
    id         INTEGER PRIMARY KEY, -- auto-increment surrogate key
    type       TEXT NOT NULL,       -- "event" | "blob"
    hash       TEXT NOT NULL,       -- event or blob hash
    pubkey     TEXT NOT NULL,       -- author pubkey
    decision   TEXT NOT NULL,       -- "accept" | "reject"
    reason     TEXT NOT NULL,       -- human-readable explanation
    checked_at INTEGER NOT NULL     -- unix timestamp
);

CREATE INDEX IF NOT EXISTS idx_audits_type ON audits(type);
CREATE INDEX IF NOT EXISTS idx_audits_hash  ON audits(hash);
CREATE INDEX IF NOT EXISTS idx_audits_pubkey    ON audits(pubkey);
CREATE INDEX IF NOT EXISTS idx_audits_checked_at ON audits(checked_at);
