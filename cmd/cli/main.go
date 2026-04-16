package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/zapstore/defender/pkg/models"
	"github.com/zapstore/defender/pkg/server/sqlite"
)

const usage = `defender-cli - manage entity policies for the defender

Usage:
  defender-cli <command>

Database:
  Uses defender.db (local db), or the path specified by the DATABASE_PATH environment variable.

Commands:
  allow   <platform> <id> <reason>   Set entity status to "allowed"
  block   <platform> <id> <reason>   Set entity status to "blocked"
  remove  <platform> <id>            Delete the policy for an entity
  get     <platform> <id>            Print the current policy for an entity
  list    [--platform <platform>] [--status <status>]   Print all policies

Examples:
  defender-cli allow  nostr <pubkey> "trusted developer"
  defender-cli block  github <username> "spam"
  defender-cli remove nostr <pubkey>
  defender-cli get    github <username>
  defender-cli list   --platform github --status allowed
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dbPath := "defender.db"
	if v := os.Getenv("DATABASE_PATH"); v != "" {
		dbPath = v
	}

	db, err := sqlite.New(sqlite.Config{Path: dbPath})
	if err != nil {
		fmt.Printf("failed to open database at path %s: %v\n", dbPath, err)
		return
	}
	defer db.Close()

	cmd := os.Args[1]
	switch cmd {
	case "allow":
		runAllow(ctx, db)

	case "block":
		runBlock(ctx, db)

	case "remove":
		runRemove(ctx, db)

	case "get":
		runGet(ctx, db)

	case "list":
		runList(ctx, db)

	default:
		fmt.Printf("unknown command: %s\n", cmd)
		fmt.Println("available commands: allow, block, remove, get, list")
	}
}

func runAllow(ctx context.Context, db sqlite.DB) {
	if len(os.Args) < 5 {
		fmt.Println("invalid command: allow <platform> <id> <reason>")
		return
	}

	entity, err := parseEntity(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	reason := strings.Join(os.Args[4:], " ")
	if reason == "" {
		fmt.Println("invalid command: reason required")
		return
	}

	policy := models.Policy{
		Entity:    entity,
		Status:    models.StatusAllowed,
		CreatedAt: time.Now().UTC(),
		AddedBy:   "cli",
		Reason:    reason,
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("successfully allowed entity")
	fmt.Printf("\tentity: %q\n", entity)
	fmt.Printf("\treason: %q\n", reason)
}

func runBlock(ctx context.Context, db sqlite.DB) {
	if len(os.Args) < 5 {
		fmt.Println("invalid command: block <platform> <id> <reason>")
		return
	}

	entity, err := parseEntity(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	reason := strings.Join(os.Args[4:], " ")
	if reason == "" {
		fmt.Println("invalid command: reason required")
		return
	}

	policy := models.Policy{
		Entity:    entity,
		Status:    models.StatusBlocked,
		CreatedAt: time.Now().UTC(),
		AddedBy:   "cli",
		Reason:    reason,
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("successfully blocked entity")
	fmt.Printf("\tentity: %q\n", entity)
	fmt.Printf("\treason: %q\n", reason)
}

func runRemove(ctx context.Context, db sqlite.DB) {
	if len(os.Args) < 4 {
		fmt.Println("invalid command: remove <platform> <id>")
		return
	}

	entity, err := parseEntity(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	deleted, err := db.DeletePolicy(ctx, entity)
	if err != nil {
		fmt.Println(err)
		return
	}

	if deleted {
		fmt.Println("successfully removed entity")
		fmt.Printf("\tentity: %q\n", entity)
	} else {
		fmt.Println("entity not found")
	}
}

func runGet(ctx context.Context, db sqlite.DB) {
	if len(os.Args) != 4 {
		fmt.Println("invalid command: get <platform> <id>")
		return
	}

	entity, err := parseEntity(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	policy, err := db.PolicyOf(ctx, entity)
	if errors.Is(err, sqlite.ErrPolicyNotFound) {
		fmt.Println("entity not found")
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(policy)
}

func runList(ctx context.Context, db sqlite.DB) {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	platformFlag := fs.String("platform", "", "filter by platform (nostr, github, gitlab, codeberg)")
	statusFlag := fs.String("status", "", "filter by status (allowed, blocked)")

	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	platform := models.Platform(*platformFlag)
	if platform != "" && !platform.IsValid() {
		fmt.Println("invalid platform:", platform)
		return
	}

	status := models.PolicyStatus(*statusFlag)
	if status != "" && !status.IsValid() {
		fmt.Println("invalid status:", status)
		return
	}

	policies, err := db.Policies(ctx, platform, status)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, p := range policies {
		fmt.Println(p)
	}
}

func parseEntity(platform, id string) (models.Entity, error) {
	entity := models.Entity{
		ID:       id,
		Platform: models.Platform(platform),
	}

	if entity.Platform == models.PlatformNostr &&
		strings.HasPrefix(entity.ID, "npub1") {
		_, v, err := nip19.Decode(entity.ID)
		if err != nil {
			return models.Entity{}, fmt.Errorf("invalid npub: %w", err)
		}
		entity.ID = v.(string)
	}

	if err := entity.Validate(); err != nil {
		return models.Entity{}, err
	}
	return entity, nil
}
