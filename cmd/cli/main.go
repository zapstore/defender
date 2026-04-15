package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/zapstore/defender/pkg/models"
	"github.com/zapstore/defender/pkg/server/sqlite"
)

const usage = `defender-cli - manage pubkey policies for the defender

Usage:
  defender-cli <command>

Database:
Uses defender.db (local db), or the path specified by the DATABASE_PATH environment variable.

Commands:
  allow   <pubkey> <reason>   Set pubkey status to "allowed"
  block   <pubkey> <reason>   Set pubkey status to "blocked"
  remove  <pubkey>            Delete the policy for a pubkey
  get     <pubkey>            Print the current policy for a pubkey
  list    <status>            Print all pubkey policies (optional status filter)

Examples:
  defender-cli allow  pk "trusted developer"
  defender-cli block  pk "spam"
  defender-cli remove pk
  defender-cli get    pk
  defender-cli list   allowed
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
	if len(os.Args) < 4 {
		fmt.Println("invalid command: allow <pubkey> <reason>")
		return
	}

	pubkey, err := parsePubkey(os.Args[2])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	reason := strings.Join(os.Args[3:], " ")
	if reason == "" {
		fmt.Println("invalid command: reason required")
		return
	}

	policy := models.PubkeyPolicy{
		Pubkey:    pubkey,
		Status:    models.StatusAllowed,
		CreatedAt: time.Now().UTC(),
		AddedBy:   "cli",
		Reason:    reason,
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("successfully allowed pubkey")
	fmt.Printf("\tpubkey: %q\n", pubkey)
	fmt.Printf("\treason: %q\n", reason)
}

func runBlock(ctx context.Context, db sqlite.DB) {
	if len(os.Args) < 4 {
		fmt.Println("invalid command: block <pubkey> <reason>")
		return
	}

	pubkey, err := parsePubkey(os.Args[2])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	reason := strings.Join(os.Args[3:], " ")
	if reason == "" {
		fmt.Println("invalid command: reason required")
		return
	}

	policy := models.PubkeyPolicy{
		Pubkey:    pubkey,
		Status:    models.StatusBlocked,
		CreatedAt: time.Now().UTC(),
		AddedBy:   "cli",
		Reason:    reason,
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("successfully blocked pubkey")
	fmt.Printf("\tpubkey: %q\n", pubkey)
	fmt.Printf("\treason: %q\n", reason)
}

func runRemove(ctx context.Context, db sqlite.DB) {
	if len(os.Args) < 3 {
		fmt.Println("invalid command: remove <pubkey>")
		return
	}

	pubkey, err := parsePubkey(os.Args[2])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	deleted, err := db.RemovePolicy(ctx, pubkey)
	if err != nil {
		fmt.Println(err)
		return
	}

	if deleted {
		fmt.Println("successfully removed pubkey")
		fmt.Printf("\tpubkey: %q\n", pubkey)
	} else {
		fmt.Println("pubkey not found")
	}
}

func runGet(ctx context.Context, db sqlite.DB) {
	if len(os.Args) != 3 {
		fmt.Println("invalid command: get <pubkey>")
		return
	}

	pubkey, err := parsePubkey(os.Args[2])
	if err != nil {
		fmt.Println("invalid command:", err)
		return
	}

	policy, err := db.PolicyOf(ctx, pubkey)
	if errors.Is(err, sqlite.ErrPolicyNotFound) {
		fmt.Println("pubkey not found")
		return
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(policy)
}

func runList(ctx context.Context, db sqlite.DB) {
	if len(os.Args) > 3 {
		fmt.Println("invalid command: list <status>")
		return
	}

	var status models.PubkeyStatus
	if len(os.Args) == 3 {
		status = models.PubkeyStatus(os.Args[2])
	}

	policies, err := db.Policies(ctx, status)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, p := range policies {
		fmt.Println(p)
	}
}

func parsePubkey(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("pubkey cannot be empty")
	}
	if strings.HasPrefix(input, "npub1") {
		_, v, err := nip19.Decode(input)
		if err != nil {
			return "", fmt.Errorf("invalid npub: %w", err)
		}
		input = v.(string)
	}
	if !nostr.IsValidPublicKey(input) {
		return "", fmt.Errorf("invalid pubkey: %s", input)
	}
	return input, nil
}
