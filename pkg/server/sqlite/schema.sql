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

CREATE TABLE IF NOT EXISTS decisions (
    id         INTEGER PRIMARY KEY, -- auto-increment surrogate key
    event_id   TEXT NOT NULL,       -- nostr event id
    pubkey     TEXT NOT NULL,       -- author pubkey
    checked_at INTEGER NOT NULL,    -- unix timestamp
    decision   TEXT NOT NULL,       -- "accept" | "reject"
    reason     TEXT NOT NULL        -- human-readable explanation
);

CREATE INDEX IF NOT EXISTS idx_decisions_event_id  ON decisions(event_id);
CREATE INDEX IF NOT EXISTS idx_decisions_pubkey    ON decisions(pubkey);
CREATE INDEX IF NOT EXISTS idx_decisions_checked_at ON decisions(checked_at);
