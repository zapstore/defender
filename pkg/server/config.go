package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	_ "github.com/joho/godotenv/autoload"
	"github.com/zapstore/defender/pkg/server/sqlite"
	"github.com/zapstore/defender/pkg/server/vertex"
)

type Config struct {
	DB     sqlite.Config
	Vertex vertex.Config
	HTTP   HTTPConfig
}

// NewConfig creates a new config with default parameters.
func NewConfig() Config {
	return Config{
		DB:     sqlite.NewConfig(),
		Vertex: vertex.NewConfig(),
		HTTP:   NewHTTPConfig(),
	}
}

// LoadConfig creates a new config with default parameters, that get overwritten by env variables when specified.
// To validate the config, call the Validate method.
func LoadConfig() (Config, error) {
	config := NewConfig()
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
	if err := c.HTTP.Validate(); err != nil {
		return fmt.Errorf("http: %w", err)
	}
	return nil
}

func (c Config) String() string {
	var b strings.Builder
	b.WriteString(c.DB.String())
	b.WriteString(c.Vertex.String())
	b.WriteString(c.HTTP.String())
	return b.String()
}

// HTTP holds the configuration for the HTTP server.
type HTTPConfig struct {
	Addr            string        `env:"HTTP_ADDR"`
	ReadTimeout     time.Duration `env:"HTTP_READ_TIMEOUT"`
	WriteTimeout    time.Duration `env:"HTTP_WRITE_TIMEOUT"`
	IdleTimeout     time.Duration `env:"HTTP_IDLE_TIMEOUT"`
	ShutdownTimeout time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT"`
	MaxBodyBytes    int64         `env:"HTTP_MAX_BODY_BYTES"`
}

func NewHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Addr:            "localhost:8080",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 5 * time.Second,
		MaxBodyBytes:    1024 * 1024, // 1 MB
	}
}

func (c HTTPConfig) Validate() error {
	if c.Addr == "" {
		return fmt.Errorf("addr is required")
	}
	if c.ReadTimeout <= time.Second {
		return fmt.Errorf("read timeout must be greater than 1 second to function reliably")
	}
	if c.WriteTimeout <= time.Second {
		return fmt.Errorf("write timeout must be greater than 1 second to function reliably")
	}
	if c.IdleTimeout <= time.Second {
		return fmt.Errorf("idle timeout must be greater than 1 second to function reliably")
	}
	if c.ShutdownTimeout <= time.Second {
		return fmt.Errorf("shutdown timeout must be greater than 1 second to function reliably")
	}
	return nil
}

func (c HTTPConfig) String() string {
	return fmt.Sprintf("HTTP:\n"+
		"\tAddr: %s\n"+
		"\tRead Timeout: %s\n"+
		"\tWrite Timeout: %s\n"+
		"\tIdle Timeout: %s\n"+
		"\tShutdown Timeout: %s\n",
		c.Addr,
		c.ReadTimeout,
		c.WriteTimeout,
		c.IdleTimeout,
		c.ShutdownTimeout,
	)
}
