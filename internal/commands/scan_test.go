package commands

import (
	"testing"
	"time"

	"github.com/ppiankov/awsspectre/internal/config"
)

// resetFlagChanged clears the Changed marker on a scanCmd flag so tests don't
// leak "explicitly set" state into each other via the shared package-level
// scanCmd/scanFlags/cfg globals.
func resetFlagChanged(t *testing.T, name string) {
	t.Helper()
	f := scanCmd.Flags().Lookup(name)
	if f == nil {
		t.Fatalf("no such flag: %s", name)
	}
	f.Changed = false
}

func TestApplyConfigDefaults_ExplicitFlagWinsOverConfigEvenAtDefaultValue(t *testing.T) {
	origFlags := scanFlags
	origCfg := cfg
	t.Cleanup(func() {
		scanFlags = origFlags
		cfg = origCfg
		resetFlagChanged(t, "idle-days")
	})

	scanFlags.idleDays = 7 // explicit value happens to equal the flag default
	cfg = config.Config{IdleDays: 14}

	if err := scanCmd.Flags().Set("idle-days", "7"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	applyConfigDefaults(scanCmd)

	if scanFlags.idleDays != 7 {
		t.Fatalf("expected explicit flag (7) to win over config (14), got %d", scanFlags.idleDays)
	}
}

func TestApplyConfigDefaults_AppliesConfigWhenFlagNotSet(t *testing.T) {
	origFlags := scanFlags
	origCfg := cfg
	t.Cleanup(func() {
		scanFlags = origFlags
		cfg = origCfg
		resetFlagChanged(t, "idle-days")
	})

	resetFlagChanged(t, "idle-days")
	scanFlags.idleDays = 7 // cobra's registered default, flag not explicitly passed
	cfg = config.Config{IdleDays: 14}

	applyConfigDefaults(scanCmd)

	if scanFlags.idleDays != 14 {
		t.Fatalf("expected config value (14) to apply when flag unset, got %d", scanFlags.idleDays)
	}
}

func TestApplyConfigDefaults_TimeoutFromConfigWhenFlagNotSet(t *testing.T) {
	origFlags := scanFlags
	origCfg := cfg
	t.Cleanup(func() {
		scanFlags = origFlags
		cfg = origCfg
		resetFlagChanged(t, "timeout")
	})

	resetFlagChanged(t, "timeout")
	scanFlags.timeout = 10 * time.Minute // cobra's registered default
	cfg = config.Config{Timeout: "30m"}

	applyConfigDefaults(scanCmd)

	if scanFlags.timeout != 30*time.Minute {
		t.Fatalf("expected config timeout (30m) to apply when flag unset, got %s", scanFlags.timeout)
	}
}

func TestApplyConfigDefaults_ExplicitTimeoutFlagWinsOverConfig(t *testing.T) {
	origFlags := scanFlags
	origCfg := cfg
	t.Cleanup(func() {
		scanFlags = origFlags
		cfg = origCfg
		resetFlagChanged(t, "timeout")
	})

	scanFlags.timeout = 10 * time.Minute // explicit value happens to equal the flag default
	cfg = config.Config{Timeout: "30m"}

	if err := scanCmd.Flags().Set("timeout", "10m"); err != nil {
		t.Fatalf("set flag: %v", err)
	}

	applyConfigDefaults(scanCmd)

	if scanFlags.timeout != 10*time.Minute {
		t.Fatalf("expected explicit flag (10m) to win over config (30m), got %s", scanFlags.timeout)
	}
}
