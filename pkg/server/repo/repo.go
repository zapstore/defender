// Package repo fetches zapstore.yaml from a repository and returns the pubkey, if present.
package repo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zapstore/defender/pkg/models"
	"gopkg.in/yaml.v3"
)

// Parsed holds the parsed components of a repository URL.
type Parsed struct {
	Entity models.Entity // Platform + owner username as ID
	Repo   string        // repository name
}

func (p Parsed) Validate() error {
	if err := p.Entity.Validate(); err != nil {
		return err
	}
	if p.Repo == "" {
		return fmt.Errorf("missing repo name")
	}
	return nil
}

// Parse parses a repository URL.
// It does not validate the returned Parsed structure.
func Parse(repoURL string) (Parsed, error) {
	u, err := url.Parse(strings.TrimSpace(repoURL))
	if err != nil {
		return Parsed{}, fmt.Errorf("failed to parse URL: %w", err)
	}

	host := strings.ToLower(u.Host)
	parts := pathParts(u.Path)
	if len(parts) < 2 {
		return Parsed{}, fmt.Errorf("URL path must contain owner and repo")
	}
	owner, repo := parts[0], parts[1]

	var platform models.Platform
	switch {
	case host == "github.com":
		platform = models.PlatformGithub
	case host == "gitlab.com" || strings.HasSuffix(host, ".gitlab.com"):
		platform = models.PlatformGitlab
	case host == "codeberg.org":
		platform = models.PlatformCodeberg
	default:
		return Parsed{}, fmt.Errorf("unsupported platform host: %s", host)
	}

	return Parsed{
		Entity: models.Entity{ID: owner, Platform: platform},
		Repo:   repo,
	}, nil
}

// Fetcher fetches zapstore.yaml from a repository.
type Fetcher struct {
	http   *http.Client
	config Config
}

// NewFetcher creates a new Fetcher with the given configuration.
func NewFetcher(c Config) *Fetcher {
	return &Fetcher{
		http:   &http.Client{Timeout: c.Timeout},
		config: c,
	}
}

// Fetch fetches zapstore.yaml from the given repository and returns the "pubkey" field (no validation).
// Returns an empty string if zapstore.yaml is absent or has no pubkey field.
func (f *Fetcher) Fetch(ctx context.Context, repo Parsed) (string, error) {
	if err := repo.Validate(); err != nil {
		return "", fmt.Errorf("Fetch: %w", err)
	}

	pk, err := f.fetchPubkey(ctx, repo)
	if err != nil {
		return "", fmt.Errorf("Fetch: %w", err)
	}
	return pk, nil
}

// Fetch fetches zapstore.yaml from the given repository URL and returns the "pubkey" field (no validation).
// Returns an empty string if zapstore.yaml is absent or has no pubkey field.
func (f *Fetcher) FetchURL(ctx context.Context, repoURL string) (string, error) {
	repo, err := Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("FetchURL: %w", err)
	}
	if err := repo.Validate(); err != nil {
		return "", fmt.Errorf("FetchURL: %w", err)
	}

	pk, err := f.fetchPubkey(ctx, repo)
	if err != nil {
		return "", fmt.Errorf("FetchURL: %w", err)
	}
	return pk, nil
}

// zapstoreYAML holds the relevant fields from zapstore.yaml.
type zapstoreYAML struct {
	Pubkey string `yaml:"pubkey"`
}

// fetchPubkey downloads zapstore.yaml from rawURL and returns the pubkey as it appears in the file, no validation.
func (f *Fetcher) fetchPubkey(ctx context.Context, repo Parsed) (string, error) {
	url := rawURL(repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}

	if repo.Entity.Platform == models.PlatformGithub && f.config.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+f.config.GitHubToken)
	}

	res, err := f.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("unexpected status %d: %s", res.StatusCode, string(body))
	}

	var z zapstoreYAML
	if err := yaml.NewDecoder(res.Body).Decode(&z); err != nil {
		return "", fmt.Errorf("failed to decode zapstore.yaml: %w", err)
	}
	return z.Pubkey, nil
}

// rawURL returns the raw content URL for zapstore.yaml given a parsed Ref.
func rawURL(p Parsed) string {
	owner, repo := p.Entity.ID, p.Repo
	switch p.Entity.Platform {
	case models.PlatformGithub:
		return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/HEAD/zapstore.yaml", owner, repo)
	case models.PlatformGitlab:
		return fmt.Sprintf("https://gitlab.com/%s/%s/-/raw/HEAD/zapstore.yaml", owner, repo)
	case models.PlatformCodeberg:
		return fmt.Sprintf("https://codeberg.org/%s/%s/raw/branch/main/zapstore.yaml", owner, repo)
	default:
		return ""
	}
}

// pathParts splits a URL path into non-empty segments.
func pathParts(p string) []string {
	var parts []string
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}
