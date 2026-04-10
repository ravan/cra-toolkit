// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"os"
	"path/filepath"
	"time"
)

// Config controls bounds, caching, and timeout behavior for transitive analysis.
// Defaults are chosen to terminate in reasonable time on real-world applications
// while allowing walks deep enough for realistic dependency chains.
type Config struct {
	MaxHopsPerPath         int           `yaml:"max_hops,omitempty"`
	MaxPathsPerFinding     int           `yaml:"max_paths,omitempty"`
	MaxTargetSymbolsPerHop int           `yaml:"max_target_symbols_per_hop,omitempty"`
	HopTimeout             time.Duration `yaml:"hop_timeout,omitempty"`
	FindingBudget          time.Duration `yaml:"finding_budget,omitempty"`
	CacheDir               string        `yaml:"cache_dir,omitempty"`
	Enabled                bool          `yaml:"enabled,omitempty"`
}

// DefaultConfig returns Config populated with the defaults documented in the
// transitive reachability design spec.
func DefaultConfig() Config {
	cacheDir := ""
	if home, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(home, "cra-toolkit", "pkgs")
	} else {
		cacheDir = filepath.Join(os.TempDir(), "cra-toolkit-pkgs")
	}
	return Config{
		MaxHopsPerPath:         8,
		MaxPathsPerFinding:     16,
		MaxTargetSymbolsPerHop: 256,
		HopTimeout:             30 * time.Second,
		FindingBudget:          5 * time.Minute,
		CacheDir:               cacheDir,
		Enabled:                true,
	}
}

// Merge overlays any non-zero fields from override onto c and returns the result.
// Used to apply product-config YAML values on top of DefaultConfig().
func (c Config) Merge(override Config) Config {
	if override.MaxHopsPerPath > 0 {
		c.MaxHopsPerPath = override.MaxHopsPerPath
	}
	if override.MaxPathsPerFinding > 0 {
		c.MaxPathsPerFinding = override.MaxPathsPerFinding
	}
	if override.MaxTargetSymbolsPerHop > 0 {
		c.MaxTargetSymbolsPerHop = override.MaxTargetSymbolsPerHop
	}
	if override.HopTimeout > 0 {
		c.HopTimeout = override.HopTimeout
	}
	if override.FindingBudget > 0 {
		c.FindingBudget = override.FindingBudget
	}
	if override.CacheDir != "" {
		c.CacheDir = override.CacheDir
	}
	return c
}
