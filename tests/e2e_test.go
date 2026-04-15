package tests

import (
	"os"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/zapstore/defender/pkg/client"
	"github.com/zapstore/defender/pkg/models"
)

var testEvent = &nostr.Event{
	Kind:      1,
	ID:        "5df0478720ef7955a139b6362ae10284e51511a0cdb66c96d526f2ec57637c51",
	PubKey:    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	CreatedAt: 1776174277,
	Tags:      []nostr.Tag{},
	Content:   "hello from the nostr army knife",
	Sig:       "9ccfef79cbd609c8fc0ffd8644c7e2dc6e5d4bced31da193cc30cb3b1e40c75eb4754739ef2fbf95def56c8440c3f3e1394b412fcc10eb6d8a5aca332f455b9b",
}

// This test assumes that the defender server is running and accessible.
// Configure the port it runs using the ADDRESS environment variable.
func TestE2E(t *testing.T) {
	addr := "http://localhost:8080"
	if v, ok := os.LookupEnv("ADDRESS"); ok {
		addr = v
	}

	client, err := client.Default(addr)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Check(testEvent)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res)

	if res.Decision != models.DecisionReject {
		t.Fatalf("expected decision to be reject, got %s", res.Decision)
	}
}
