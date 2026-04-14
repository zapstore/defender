package sqlite

import "fmt"

type Config struct {
	Path string `env:"DATABASE_PATH"`
}

func NewConfig() Config {
	return Config{
		Path: "defender.db",
	}
}

func (c Config) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}

func (c Config) String() string {
	return fmt.Sprintf("Database:\n"+
		"\tPath: %s\n",
		c.Path,
	)
}
