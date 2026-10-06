package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/dolonet/mtg-multi/internal/config"
)

// ReadConfig reads, parses and validates the config file. When
// MTG_CONFIG_OVERLAY points to a TOML file, it is merged under the config
// (keys of the config always win, see config.MergeOverlay). Every config read
// (start, SIGHUP, POST /reload, doctor, access) goes through here, so the
// overlay applies the same way everywhere.
func ReadConfig(path string) (*config.Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	if overlayPath := strings.TrimSpace(os.Getenv(config.EnvConfigOverlay)); overlayPath != "" {
		overlay, err := os.ReadFile(overlayPath)
		if err != nil {
			return nil, fmt.Errorf("cannot read config overlay %s (%s): %w", overlayPath, config.EnvConfigOverlay, err)
		}

		content, err = config.MergeOverlay(content, overlay)
		if err != nil {
			return nil, fmt.Errorf("cannot apply config overlay %s (%s): %w", overlayPath, config.EnvConfigOverlay, err)
		}
	}

	conf, err := config.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("cannot parse config: %w", err)
	}

	if err := conf.ApplyEnvironment(); err != nil {
		return nil, fmt.Errorf("cannot apply environment variables: %w", err)
	}

	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return conf, nil
}
