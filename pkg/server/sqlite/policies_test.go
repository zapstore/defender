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
		Entity: models.Entity{
			ID:       "github-account",
			Platform: models.PlatformGithub,
		},
		Status:    models.StatusAllowed,
		CreatedAt: time.Unix(time.Now().Unix(), 0),
		AddedBy:   "cli",
		Reason:    "trusted developer",
	}
	policyBlocked = models.Policy{
		Entity: models.Entity{
			ID:       "pubkey",
			Platform: models.PlatformNostr,
		},
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

	got, err := db.PolicyOf(ctx, policyAllowed.Entity)
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

	all, err := db.Policies(ctx, "", "")
	if err != nil {
		t.Fatalf("Policies: %v", err)
	}

	expected := []models.Policy{policyAllowed, policyBlocked}
	if !reflect.DeepEqual(all, expected) {
		t.Fatalf("expected 2 policies, got %d", len(all))
	}

	allowed, err := db.Policies(ctx, "", models.StatusAllowed)
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

	if err := db.SetPolicy(ctx, policyAllowed); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	allowed, err := db.IsAllowed(ctx, policyAllowed.Entity)
	if err != nil {
		t.Fatalf("IsAllowed: %v", err)
	}
	if !allowed {
		t.Error("IsAllowed: got false, want true")
	}

	blocked, err := db.IsBlocked(ctx, policyAllowed.Entity)
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if blocked {
		t.Error("IsBlocked: got true, want false")
	}
}

func TestSetAndDeletePolicy(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	if err := db.SetPolicy(ctx, policyAllowed); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// First removal: the row exists, should report deleted=true.
	deleted, err := db.DeletePolicy(ctx, policyAllowed.Entity)
	if err != nil {
		t.Fatalf("RemovePolicy (first): %v", err)
	}
	if !deleted {
		t.Error("RemovePolicy (first): got false, want true")
	}

	// PolicyOf should now return ErrPolicyNotFound.
	_, err = db.PolicyOf(ctx, policyAllowed.Entity)
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("PolicyOf after remove: got %v, want ErrPolicyNotFound", err)
	}

	// Second removal: nothing to delete, should report deleted=false.
	deleted, err = db.DeletePolicy(ctx, policyAllowed.Entity)
	if err != nil {
		t.Fatalf("RemovePolicy (second): %v", err)
	}
	if deleted {
		t.Error("RemovePolicy (second): got true, want false")
	}
}
