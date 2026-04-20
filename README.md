# Defender

## Overview

Defender is a policy and security service for the Zapstore Nostr relay. It acts as a decision layer between event ingestion and persistence, combining fast admission checks with asynchronous analysis to detect spam, scams, and malicious content (WIP).

## Why it exists

As the relay evolved, basic whitelist and blacklist checks became insufficient. Trust decisions now depend on multiple factors: external reputation signals, repository validation, and delayed malware analysis.

Embedding this logic directly into the relay would make it complex, slow, and difficult to extend. Defender exists to separate these concerns, allowing trust and safety rules to evolve independently from the core relay while supporting both immediate decisions and deferred corrective actions.

## Where to draw the line

The relay owns everything it can answer locally, cheaply, and without knowing anything about the outside world.

The defender owns everything that requires external knowledge, accumulated history, or expensive computation about an author or their content.

## Goals

- **Control access to the relay**
  - Apply immediate admission decisions based on whitelist, blacklist, and reputation signals.
  - Support integration with external scoring providers like Vertex.

- **Support asynchronous threat detection**
  - Run slower, deeper analysis such as malware detection and behavioral signals after ingestion.
  - Continuously improve detection using new data sources and heuristics.

- **Enable reactive enforcement**
  - Issue post-publication actions such as revocation or deletion when malicious activity is detected.
  - Maintain consistency between detected threats and relay state.

## Design Principles

- Fast path decisions must be low-latency and resilient to external failures.
- Expensive checks are handled asynchronously and should not block ingestion.
- All decisions must be logged for auditability.
- The system should evolve without requiring changes to the relay core.

## Developing

Make a `.env` file, customize it to your needs and fill in the required variables.
You can take a look at the `.env.example` for the list of supported variables with their default values.

To run the server or CLI locally without building a binary, `cd` into the relevant command directory and use `go run .`:

The server listens on `localhost:8080` by default.

## Building

Binaries are built using the Makefile. The build always targets a specific git tag. The script checks out that tag before compiling, so the binary is guaranteed to reflect a clean, tagged commit.

```bash
make defender      # builds the server binary
make defender-cli  # builds the CLI binary
make all           # builds both
```

By default, the latest tag is resolved automatically via `git describe`. You can also target a specific tag explicitly:

```bash
make defender TAG=v1.2.3
```

Built binaries are placed in the `build/` directory and named after the tag, e.g. `build/defender-v1.2.3`. The git tag is also embedded into the binary at compile time and exposed via the `GET /v1/health` endpoint.

## CLI

The `defender-cli` tool manages entity policies directly against the local database.

By default the CLI uses `defender.db` in the current directory. Override with the `DATABASE_PATH` environment variable.

## API

### `POST /v1/events/check`

Evaluates a Nostr event and returns an admission decision.

**Request body** — a JSON-encoded Nostr event:

```jsonc
{
  "id": "...",
  "pubkey": "...",
  "created_at": 1700000000,
  "kind": 1,
  "tags": [],
  "content": "...",
  "sig": "..."
}
```

**Response**:

```jsonc
{
  "decision": "accept" | "reject",
  "reason": "human readable explanation"
}
```

---

### `GET /v1/policies`

Returns all policies. Accepts optional query parameters to filter results:

- `?platform=nostr|github|gitlab|codeberg`
- `?status=allowed|blocked`

Both filters can be combined: `?platform=github&status=blocked`.

**Response**:

```jsonc
[
  {
    "id": "...",
    "platform": "nostr" | "github" | "gitlab" | "codeberg",
    "status": "allowed" | "blocked",
    "reason": "...",
    "added_by": "...",
    "created_at": 1700000000
  }
]
```

---

### `GET /v1/policies/{platform}/{id}`

Returns the policy for a specific entity.

**Response**: a single policy object as above. Returns `404` if no policy exists for the entity.

---

### `PUT /v1/policies/{platform}/{id}`

Creates or updates the policy for an entity.

**Request body**:

```jsonc
{
  "status": "allowed" | "blocked",
  "reason": "...",
  "added_by": "..."
}
```

**Response**: `204 No Content` on success.

---

### `DELETE /v1/policies/{platform}/{id}`

Removes the policy for an entity. Returns `204 No Content` regardless of whether the policy existed.
