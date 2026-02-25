package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "" {
		t.Fatalf("expected empty profile, got %q", cfg.Profile)
	}
	if cfg.IdleDays != 0 {
		t.Fatalf("expected zero idle_days, got %d", cfg.IdleDays)
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	content := `profile: production
regions:
  - us-east-1
  - eu-west-1
idle_days: 14
stale_days: 60
min_monthly_cost: 5.0
format: json
timeout: 5m
exclude:
  resource_ids:
    - i-0abc123
  tags:
    - "Environment=production"
`
	if err := os.WriteFile(filepath.Join(dir, ".awsspectre.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "production" {
		t.Fatalf("expected profile production, got %q", cfg.Profile)
	}
	if len(cfg.Regions) != 2 {
		t.Fatalf("expected 2 regions, got %d", len(cfg.Regions))
	}
	if cfg.IdleDays != 14 {
		t.Fatalf("expected idle_days 14, got %d", cfg.IdleDays)
	}
	if cfg.StaleDays != 60 {
		t.Fatalf("expected stale_days 60, got %d", cfg.StaleDays)
	}
	if cfg.MinMonthlyCost != 5.0 {
		t.Fatalf("expected min_monthly_cost 5.0, got %f", cfg.MinMonthlyCost)
	}
	if cfg.Format != "json" {
		t.Fatalf("expected format json, got %q", cfg.Format)
	}
	if len(cfg.Exclude.ResourceIDs) != 1 {
		t.Fatalf("expected 1 excluded resource ID, got %d", len(cfg.Exclude.ResourceIDs))
	}
	if len(cfg.Exclude.Tags) != 1 {
		t.Fatalf("expected 1 excluded tag, got %d", len(cfg.Exclude.Tags))
	}
}

func TestLoad_YMLExtension(t *testing.T) {
	dir := t.TempDir()
	content := `profile: staging
idle_days: 3
`
	if err := os.WriteFile(filepath.Join(dir, ".awsspectre.yml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profile != "staging" {
		t.Fatalf("expected profile staging, got %q", cfg.Profile)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	content := `[invalid yaml content`
	if err := os.WriteFile(filepath.Join(dir, ".awsspectre.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_YAMLPriority(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `profile: from-yaml`
	ymlContent := `profile: from-yml`
	if err := os.WriteFile(filepath.Join(dir, ".awsspectre.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".awsspectre.yml"), []byte(ymlContent), 0o644); err != nil {
		t.Fatalf("write yml: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// .yaml should take priority over .yml
	if cfg.Profile != "from-yaml" {
		t.Fatalf("expected profile from-yaml (priority), got %q", cfg.Profile)
	}
}

func TestConfig_TimeoutDuration(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		wantSec float64
	}{
		{"empty", "", 0},
		{"5m", "5m", 300},
		{"30s", "30s", 30},
		{"invalid", "notaduration", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Timeout: tt.timeout}
			got := cfg.TimeoutDuration().Seconds()
			if got != tt.wantSec {
				t.Fatalf("expected %f seconds, got %f", tt.wantSec, got)
			}
		})
	}
}
