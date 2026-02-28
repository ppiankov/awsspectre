package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds awsspectre configuration loaded from .awsspectre.yaml.
type Config struct {
	Regions              []string `yaml:"regions"`
	Profile              string   `yaml:"profile"`
	IdleDays             int      `yaml:"idle_days"`
	StaleDays            int      `yaml:"stale_days"`
	MinMonthlyCost       float64  `yaml:"min_monthly_cost"`
	IdleCPUThreshold     float64  `yaml:"idle_cpu_threshold"`
	HighMemoryThreshold  float64  `yaml:"high_memory_threshold"`
	StoppedThresholdDays int      `yaml:"stopped_threshold_days"`
	Format               string   `yaml:"format"`
	Timeout              string   `yaml:"timeout"`
	Exclude              Exclude  `yaml:"exclude"`
}

// Exclude defines resources to skip during scanning.
type Exclude struct {
	ResourceIDs []string `yaml:"resource_ids"`
	Tags        []string `yaml:"tags"`
}

// ParseTags converts tag strings ("Key=Value" or "Key") into a map.
// Key-only entries have an empty string value, meaning "match any value".
func (e Exclude) ParseTags() map[string]string {
	if len(e.Tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(e.Tags))
	for _, s := range e.Tags {
		if k, v, ok := strings.Cut(s, "="); ok {
			m[k] = v
		} else {
			m[s] = ""
		}
	}
	return m
}

// TimeoutDuration parses the timeout string as a duration.
func (c Config) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

// Load searches for .awsspectre.yaml or .awsspectre.yml in the given directory
// and returns the parsed config. Returns an empty Config if no file is found.
func Load(dir string) (Config, error) {
	candidates := []string{
		filepath.Join(dir, ".awsspectre.yaml"),
		filepath.Join(dir, ".awsspectre.yml"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}

		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
		return cfg, nil
	}

	return Config{}, nil
}
