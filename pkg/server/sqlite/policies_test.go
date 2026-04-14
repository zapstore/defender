package sqlite

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

var ctx = context.Background()

func TestPolicyRoundrip(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	policy := PubkeyPolicy{
		Pubkey:    "abc123",
		Status:    StatusAllowed,
		CreatedAt: time.Unix(time.Now().Unix(), 0), // truncate to seconds to match DB precision
		AddedBy:   "cli",
		Reason:    "trusted developer",
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	got, err := db.PolicyOf(ctx, policy.Pubkey)
	if err != nil {
		t.Fatalf("PolicyOf: %v", err)
	}

	if !reflect.DeepEqual(policy, got) {
		t.Errorf("Policy mismatch: got %v, want %v", got, policy)
	}
}

func TestIsAllowed(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	policy := PubkeyPolicy{
		Pubkey:    "abc123",
		Status:    StatusAllowed,
		CreatedAt: time.Now(),
		AddedBy:   "cli",
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	allowed, err := db.IsAllowed(ctx, policy.Pubkey)
	if err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if !allowed {
		t.Error("IsAllowed: got false, want true")
	}

	blocked, err := db.IsBlocked(ctx, policy.Pubkey)
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if blocked {
		t.Error("IsBlocked: got true, want false")
	}
}

func TestIsBlocked(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	policy := PubkeyPolicy{
		Pubkey:    "def456",
		Status:    StatusBlocked,
		CreatedAt: time.Now(),
		AddedBy:   "system",
		Reason:    "spam",
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	blocked, err := db.IsBlocked(ctx, policy.Pubkey)
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if !blocked {
		t.Error("IsBlocked: got false, want true")
	}

	allowed, err := db.IsAllowed(ctx, policy.Pubkey)
	if err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if allowed {
		t.Error("IsAllowed: got true, want false")
	}
}

func TestSetAndRemovePolicy(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	policy := PubkeyPolicy{
		Pubkey:    "ghi789",
		Status:    StatusBlocked,
		CreatedAt: time.Now(),
		AddedBy:   "cli",
		Reason:    "malicious",
	}

	if err := db.SetPolicy(ctx, policy); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// First removal: the row exists, should report deleted=true.
	deleted, err := db.RemovePolicy(ctx, policy.Pubkey)
	if err != nil {
		t.Fatalf("RemovePolicy (first): %v", err)
	}
	if !deleted {
		t.Error("RemovePolicy (first): got false, want true")
	}

	// PolicyOf should now return ErrPubkeyPolicyNotFound.
	_, err = db.PolicyOf(ctx, policy.Pubkey)
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("PolicyOf after remove: got %v, want ErrPubkeyPolicyNotFound", err)
	}

	// Second removal: nothing to delete, should report deleted=false.
	deleted, err = db.RemovePolicy(ctx, policy.Pubkey)
	if err != nil {
		t.Fatalf("RemovePolicy (second): %v", err)
	}
	if deleted {
		t.Error("RemovePolicy (second): got true, want false")
	}
}
