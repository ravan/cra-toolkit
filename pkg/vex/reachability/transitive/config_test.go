// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"
	"time"
)

func TestDefaultConfig_Bounds(t *testing.T) {
	c := DefaultConfig()
	if c.MaxHopsPerPath != 8 {
		t.Errorf("MaxHopsPerPath: expected 8, got %d", c.MaxHopsPerPath)
	}
	if c.MaxPathsPerFinding != 16 {
		t.Errorf("MaxPathsPerFinding: expected 16, got %d", c.MaxPathsPerFinding)
	}
	if c.MaxTargetSymbolsPerHop != 256 {
		t.Errorf("MaxTargetSymbolsPerHop: expected 256, got %d", c.MaxTargetSymbolsPerHop)
	}
	if c.HopTimeout != 30*time.Second {
		t.Errorf("HopTimeout: expected 30s, got %s", c.HopTimeout)
	}
	if c.FindingBudget != 5*time.Minute {
		t.Errorf("FindingBudget: expected 5m, got %s", c.FindingBudget)
	}
	if c.CacheDir == "" {
		t.Errorf("CacheDir should have a default")
	}
}

func TestDegradationReasons_AreDistinct(t *testing.T) {
	reasons := []string{
		ReasonTransitiveNotApplicable,
		ReasonManifestFetchFailed,
		ReasonTarballFetchFailed,
		ReasonDigestMismatch,
		ReasonSourceUnavailable,
		ReasonBoundExceeded,
		ReasonExtractorError,
		ReasonPathBroken,
		ReasonNoApplicationRoot,
	}
	seen := make(map[string]bool)
	for _, r := range reasons {
		if r == "" {
			t.Errorf("reason should not be empty")
		}
		if seen[r] {
			t.Errorf("duplicate reason: %q", r)
		}
		seen[r] = true
	}
}

func TestConfig_Merge(t *testing.T) {
	base := DefaultConfig()
	override := Config{
		MaxHopsPerPath: 20,
		HopTimeout:     time.Minute,
		CacheDir:       "/tmp/custom",
	}
	got := base.Merge(override)
	if got.MaxHopsPerPath != 20 {
		t.Errorf("MaxHopsPerPath: expected 20, got %d", got.MaxHopsPerPath)
	}
	if got.HopTimeout != time.Minute {
		t.Errorf("HopTimeout: expected 1m, got %s", got.HopTimeout)
	}
	if got.CacheDir != "/tmp/custom" {
		t.Errorf("CacheDir: expected /tmp/custom, got %q", got.CacheDir)
	}
	if got.MaxPathsPerFinding != base.MaxPathsPerFinding {
		t.Errorf("MaxPathsPerFinding: expected %d (unchanged), got %d", base.MaxPathsPerFinding, got.MaxPathsPerFinding)
	}
}
