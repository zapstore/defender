package tests

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pippellia-btc/blossom"
	"github.com/zapstore/defender/pkg/client"
	"github.com/zapstore/defender/pkg/models"
)

// The following test the client methods against a running server.
// The server address is read from the ADDRESS environment variable, defaulting to localhost:8080.

var (
	ctx  = context.Background()
	addr = "localhost:8080"
	pip  = "f683e87035f7ad4f44e0b98cfbd9537e16455a92cd38cefc4cb31db7557f5ef2"
	gigi = "6e468422dfb74a5738702a8823b9b28168abab8655faacb6853cd0ee15deee93"

	// The event is signed by the nak key, which has been leaked, so it should not pass full vertex validation.
	appEvent = &nostr.Event{
		Kind:      models.KindApp,
		ID:        "c5fb9e11fff18013d7256fa7d6e641e2b21eb5667a7f95726924dd45874ca1d2",
		PubKey:    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		CreatedAt: 1776346594,
		Tags:      []nostr.Tag{},
		Sig:       "c7b7a6b2b84a3980d2645b808440ffac15d8263b226dbbd66797c8bb525140d188784e7a5190f99f2f95d8aaa5187864efec062b9c1d78595d72dd723f0c34e1",
	}

	hash = blossom.ComputeHash([]byte("this is a blob innit"))

	blob = models.BlobMeta{
		Pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Hash:   hash,
		Size:   int64(len("this is a blob innit")),
		Type:   "text/plain",
	}
)

func init() {
	if v, ok := os.LookupEnv("ADDRESS"); ok {
		addr = v
	}
}

func TestHealth(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)
}

func TestCheckEvent(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.CheckEvent(ctx, appEvent)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)

	if res.Decision != models.DecisionReject {
		t.Fatalf("expected decision to be reject, got %s", res.Decision)
	}
}

func TestCheckBlob(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.CheckBlob(ctx, blob)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)

	if res.Decision != models.DecisionReject {
		t.Fatalf("expected decision to be reject, got %s", res.Decision)
	}
}

func TestListPolicies(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	total, err := client.ListPolicies(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := client.ListPolicies(ctx, "", models.StatusAllowed)
	if err != nil {
		t.Fatal(err)
	}

	blocked, err := client.ListPolicies(ctx, "", models.StatusBlocked)
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
		Entity: models.Entity{
			ID:       pip,
			Platform: models.PlatformNostr,
		},
		Status:  models.StatusAllowed,
		Reason:  "because I am building it",
		AddedBy: "myself",
	}

	if err := client.SetPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}

	got, err := client.GetPolicy(ctx, policy.Entity)
	if err != nil {
		t.Fatal(err)
	}
	if got.Entity.ID != policy.Entity.ID {
		t.Fatalf("expected pubkey %s, got %s", policy.Entity.ID, got.Entity.ID)
	}
	if got.Entity.Platform != policy.Entity.Platform {
		t.Fatalf("expected platform %s, got %s", policy.Entity.Platform, got.Entity.Platform)
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

func TestGetPolicyNotFound(t *testing.T) {
	c, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	entity := models.Entity{
		ID:       gigi,
		Platform: models.PlatformNostr,
	}
	_, err = c.GetPolicy(ctx, entity)
	if !errors.Is(err, client.ErrPolicyNotFound) {
		t.Fatalf("expected error %v, got %v", client.ErrPolicyNotFound, err)
	}
}

func TestDeletePolicy(t *testing.T) {
	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	entity := models.Entity{
		ID:       gigi,
		Platform: models.PlatformNostr,
	}

	if err := client.DeletePolicy(ctx, entity); err != nil {
		t.Fatal(err)
	}

	all, err := client.ListPolicies(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, p := range all {
		if reflect.DeepEqual(p.Entity, entity) {
			found = true
			break
		}
	}

	if found {
		t.Fatalf("expected pubkey %s to be deleted from the list of all pubkeys", pip)
	}
}
