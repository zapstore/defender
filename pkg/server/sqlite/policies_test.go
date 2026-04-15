package sqlite

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zapstore/defender/pkg/models"
)

var (
	ctx           = context.Background()
	policyAllowed = models.Policy{
		Pubkey:    "aaaaaa",
		Status:    models.StatusAllowed,
		CreatedAt: time.Unix(time.Now().Unix(), 0),
		AddedBy:   "cli",
		Reason:    "trusted developer",
	}
	policyBlocked = models.Policy{
		Pubkey:    "bbbbbb",
		Status:    models.StatusBlocked,
		CreatedAt: time.Unix(time.Now().Unix(), 0),
		AddedBy:   "system",
		Reason:    "spam",
	}
)

func TestSetReadPolicy(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	if err := db.SetPolicy(ctx, policyAllowed); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	got, err := db.PolicyOf(ctx, policyAllowed.Pubkey)
	if err != nil {
		t.Fatalf("PolicyOf: %v", err)
	}

	if !reflect.DeepEqual(policyAllowed, got) {
		t.Errorf("Policy mismatch: got %v, want %v", got, policyAllowed)
	}
}

func TestPolicies(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	if err := db.SetPolicy(ctx, policyAllowed); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if err := db.SetPolicy(ctx, policyBlocked); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	all, err := db.Policies(ctx, "")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}

	expected := []models.Policy{policyAllowed, policyBlocked}
	if !reflect.DeepEqual(all, expected) {
		t.Fatalf("expected 2 policies, got %d", len(all))
	}

	allowed, err := db.Policies(ctx, models.StatusAllowed)
	if err != nil {
		t.Fatalf("PubkeysAllowed: %v", err)
	}

	expected = []models.Policy{policyAllowed}
	if !reflect.DeepEqual(allowed, expected) {
		t.Fatalf("expected allowed: %v, got %v", expected, allowed)
	}
}

func TestIsChecks(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	policy := models.Policy{
		Pubkey:    "abc123",
		Status:    models.StatusAllowed,
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

func TestSetAndRemovePolicy(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	policy := models.Policy{
		Pubkey:    "ghi789",
		Status:    models.StatusBlocked,
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

	// PolicyOf should now return ErrPolicyNotFound.
	_, err = db.PolicyOf(ctx, policy.Pubkey)
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("PolicyOf after remove: got %v, want ErrPolicyNotFound", err)
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
