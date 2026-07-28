package aws

import (
	"strings"
	"testing"
	"time"
)

func TestIdleWindowDescription_ExactlyAtBoundary(t *testing.T) {
	now := time.Now().UTC()
	createTime := now.Add(-7 * 24 * time.Hour) // running for exactly 7 days
	desc, sufficient := idleWindowDescription(7, &createTime, now)
	if !sufficient {
		t.Fatalf("expected sufficient=true when age equals idleDays exactly, got false (desc=%q)", desc)
	}
	if desc != "7 days" {
		t.Fatalf("expected full-window description at the exact boundary, got %q", desc)
	}
}

func TestIdleWindowDescription_ZeroIdleDays(t *testing.T) {
	now := time.Now().UTC()
	createTime := now.Add(-1 * time.Minute)
	desc, sufficient := idleWindowDescription(0, &createTime, now)
	if !sufficient {
		t.Fatalf("expected sufficient=true for a zero-length configured window, got false (desc=%q)", desc)
	}
	if desc != "0 days" {
		t.Fatalf("expected \"0 days\", got %q", desc)
	}
}

func TestIdleWindowDescription_FutureCreateTime_ClockSkew(t *testing.T) {
	now := time.Now().UTC()
	createTime := now.Add(1 * time.Hour) // create time in the future — clock skew
	desc, sufficient := idleWindowDescription(7, &createTime, now)
	if sufficient {
		t.Fatalf("expected sufficient=false for a create time in the future, got true (desc=%q)", desc)
	}
	if !strings.Contains(desc, "1 minutes") {
		t.Fatalf("expected clock skew to be treated as zero observed age, got %q", desc)
	}
}

func TestIdleWindowDescription_NilCreateTime_DefaultsToSufficient(t *testing.T) {
	now := time.Now().UTC()
	desc, sufficient := idleWindowDescription(7, nil, now)
	if !sufficient {
		t.Fatalf("expected sufficient=true when createTime is nil, got false (desc=%q)", desc)
	}
	if desc != "7 days" {
		t.Fatalf("expected full-window description when createTime is nil, got %q", desc)
	}
}

func TestFormatDuration_MinutesBranch(t *testing.T) {
	if got := formatDuration(11 * time.Minute); got != "11 minutes" {
		t.Fatalf("expected \"11 minutes\", got %q", got)
	}
	if got := formatDuration(30 * time.Second); got != "1 minutes" {
		t.Fatalf("expected sub-minute durations to floor to \"1 minutes\", got %q", got)
	}
}

func TestFormatDuration_HoursBranch(t *testing.T) {
	if got := formatDuration(5 * time.Hour); got != "5 hours" {
		t.Fatalf("expected \"5 hours\", got %q", got)
	}
	if got := formatDuration(23 * time.Hour); got != "23 hours" {
		t.Fatalf("expected \"23 hours\", got %q", got)
	}
}

func TestFormatDuration_DaysBranch(t *testing.T) {
	if got := formatDuration(24 * time.Hour); got != "1 days" {
		t.Fatalf("expected \"1 days\", got %q", got)
	}
	if got := formatDuration(10 * 24 * time.Hour); got != "10 days" {
		t.Fatalf("expected \"10 days\", got %q", got)
	}
}
