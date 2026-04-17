package repo

import (
	"context"
	"testing"

	"github.com/zapstore/defender/pkg/models"
)

var ctx = context.Background()

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		isValid  bool
		expected Parsed
	}{
		{
			name:    "valid github URL",
			url:     "https://github.com/owner/myrepo",
			isValid: true,
			expected: Parsed{
				Entity: models.Entity{ID: "owner", Platform: models.PlatformGithub},
				Repo:   "myrepo",
			},
		},
		{
			name:    "valid github URL with trailing slash",
			url:     "https://github.com/owner/myrepo/",
			isValid: true,
			expected: Parsed{
				Entity: models.Entity{ID: "owner", Platform: models.PlatformGithub},
				Repo:   "myrepo",
			},
		},
		{
			name:    "valid github URL with extra path segments",
			url:     "https://github.com/owner/myrepo/tree/main",
			isValid: true,
			expected: Parsed{
				Entity: models.Entity{ID: "owner", Platform: models.PlatformGithub},
				Repo:   "myrepo",
			},
		},
		{
			name:    "valid gitlab URL",
			url:     "https://gitlab.com/owner/myrepo",
			isValid: true,
			expected: Parsed{
				Entity: models.Entity{ID: "owner", Platform: models.PlatformGitlab},
				Repo:   "myrepo",
			},
		},
		{
			name:    "valid codeberg URL",
			url:     "https://codeberg.org/owner/myrepo",
			isValid: true,
			expected: Parsed{
				Entity: models.Entity{ID: "owner", Platform: models.PlatformCodeberg},
				Repo:   "myrepo",
			},
		},
		{
			name:    "leading and trailing whitespace",
			url:     "  https://github.com/owner/myrepo  ",
			isValid: true,
			expected: Parsed{
				Entity: models.Entity{ID: "owner", Platform: models.PlatformGithub},
				Repo:   "myrepo",
			},
		},
		{
			name:    "unsupported platform",
			url:     "https://bitbucket.org/owner/myrepo",
			isValid: false,
		},
		{
			name:    "missing repo segment",
			url:     "https://github.com/owner",
			isValid: false,
		},
		{
			name:    "empty path",
			url:     "https://github.com/",
			isValid: false,
		},
		{
			name:    "empty URL",
			url:     "",
			isValid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse(test.url)

			if test.isValid && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if !test.isValid && err == nil {
				t.Fatalf("expected an error, got none (result: %+v)", got)
			}

			if got != test.expected {
				t.Errorf("Parse() = %+v, want %+v", got, test.expected)
			}
		})
	}
}

func TestE2E(t *testing.T) {
	repoURL := "https://github.com/pippellia-btc/TEST"
	expectedPk := "8d555b569d5c4c28c7d489e1d581248b1469d3fce288f32d50dbc53869f32e0e"

	config := NewConfig()
	fetcher := NewFetcher(config)

	repo, err := Parse(repoURL)
	if err != nil {
		t.Fatal(err)
	}

	if err := repo.Validate(); err != nil {
		t.Fatal(err)
	}

	pubkey, err := fetcher.Fetch(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	if pubkey != expectedPk {
		t.Errorf("pubkey mismatch: got %v, want %v", pubkey, expectedPk)
	}
}
