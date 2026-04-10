// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package transitive provides configuration and helpers for transitive
// dependency reachability analysis across package ecosystems.
package transitive

import (
	"os"
	"path/filepath"
)

// Config controls transitive reachability analysis behaviour.
type Config struct {
	// Enabled, when false, disables transitive reachability analysis and
	// preserves direct-only behaviour. Defaults to true.
	Enabled bool
	// CacheDir is the directory used to cache fetched package tarballs.
	// Defaults to ~/.cache/cra-toolkit/pkgs.
	CacheDir string
}

// DefaultConfig returns a Config with production-safe defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:  true,
		CacheDir: defaultCacheDir(),
	}
}

// defaultCacheDir returns the platform default cache directory for fetched
// package tarballs.
func defaultCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "cra-toolkit", "pkgs")
	}
	return filepath.Join(os.TempDir(), "cra-toolkit", "pkgs")
}
