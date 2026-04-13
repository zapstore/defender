// The package config is responsible for loading package specific configs from the
// environment variables, and validating them.
//
// Packages requiring configs should expose:
// - A Config struct with the package specific config parameters.
// - A NewConfig() function to create a new Config with default parameters.
// - A Validate() method to validate the config.
// - A String() method to return a string representation of the config.
package config

import (
	"fmt"
	"strings"

	"github.com/caarlos0/env/v11"
	_ "github.com/joho/godotenv/autoload"
	"github.com/zapstore/defender/pkg/server/db"
	"github.com/zapstore/defender/pkg/server/vertex"
)

type Config struct {
	DB     db.Config
	Vertex vertex.Config
}

// New creates a new [Config] with default parameters.
func New() Config {
	return Config{
		DB:     db.NewConfig(),
		Vertex: vertex.NewConfig(),
	}
}

// Load creates a new [Config] with default parameters, that get overwritten by env variables when specified.
// To validate the config, call [Config.Validate].
func Load() (Config, error) {
	config := New()
	if err := env.Parse(&config); err != nil {
		return Config{}, fmt.Errorf("failed to load config: %w", err)
	}
	return config, nil
}

func (c Config) Validate() error {
	if err := c.DB.Validate(); err != nil {
		return fmt.Errorf("db: %w", err)
	}
	if err := c.Vertex.Validate(); err != nil {
		return fmt.Errorf("vertex: %w", err)
	}
	return nil
}

func (c Config) String() string {
	var b strings.Builder
	b.WriteString(c.DB.String())
	b.WriteString(c.Vertex.String())
	return b.String()
}
