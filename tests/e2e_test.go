package tests

import (
	"context"
	"os"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/zapstore/defender/pkg/client"
	"github.com/zapstore/defender/pkg/models"
)

// The following test the client methods against a running server.
// The server address is read from the ADDRESS environment variable, defaulting to localhost:8080.

var (
	ctx  = context.Background()
	addr = "http://localhost:8080"
	pip  = "f683e87035f7ad4f44e0b98cfbd9537e16455a92cd38cefc4cb31db7557f5ef2"

	// The event is signed by the nak key, which has been leaked.
	testEvent = &nostr.Event{
		Kind:      1,
		ID:        "5df0478720ef7955a139b6362ae10284e51511a0cdb66c96d526f2ec57637c51",
		PubKey:    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		CreatedAt: 1776174277,
		Tags:      []nostr.Tag{},
		Content:   "hello from the nostr army knife",
		Sig:       "9ccfef79cbd609c8fc0ffd8644c7e2dc6e5d4bced31da193cc30cb3b1e40c75eb4754739ef2fbf95def56c8440c3f3e1394b412fcc10eb6d8a5aca332f455b9b",
	}
)

func init() {
	if v, ok := os.LookupEnv("ADDRESS"); ok {
		addr = v
	}
}

func TestCheck(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Check(ctx, testEvent)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)

	if res.Decision != models.DecisionReject {
		t.Fatalf("expected decision to be reject, got %s", res.Decision)
	}
}

func TestPubkeys(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	total, err := client.Pubkeys(ctx, "")
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := client.Pubkeys(ctx, models.StatusAllowed)
	if err != nil {
		t.Fatal(err)
	}

	blocked, err := client.Pubkeys(ctx, models.StatusBlocked)
	if err != nil {
		t.Fatal(err)
	}

	if len(total) != len(allowed)+len(blocked) {
		t.Fatalf("expected total pubkey policies to be sum of allowed and blocked, got %d != %d + %d", len(total), len(allowed), len(blocked))
	}
}

func TestSetGetPolicy(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	policy := models.Policy{
		Pubkey:  pip,
		Status:  models.StatusAllowed,
		Reason:  "because I am building it",
		AddedBy: "myself",
	}

	if err := client.SetPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}

	got, err := client.GetPolicy(ctx, policy.Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pubkey != policy.Pubkey {
		t.Fatalf("expected pubkey %s, got %s", policy.Pubkey, got.Pubkey)
	}
	if got.Status != policy.Status {
		t.Fatalf("expected status %s, got %s", policy.Status, got.Status)
	}
	if got.Reason != policy.Reason {
		t.Fatalf("expected reason %s, got %s", policy.Reason, got.Reason)
	}
	if got.AddedBy != policy.AddedBy {
		t.Fatalf("expected added_by %s, got %s", policy.AddedBy, got.AddedBy)
	}
	// CreatedAt is set by the server, so we can't compare it directly
}

func TestDeletePolicy(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.DeletePolicy(ctx, pip); err != nil {
		t.Fatal(err)
	}

	all, err := client.Pubkeys(ctx, "")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, p := range all {
		if p.Pubkey == pip {
			found = true
			break
		}
	}

	if found {
		t.Fatalf("expected pubkey %s to be deleted from the list of all pubkeys", pip)
	}
}
