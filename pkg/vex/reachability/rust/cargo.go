// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// CargoMetadata holds parsed Cargo.toml feature and dependency information.
type CargoMetadata struct {
	Features        map[string][]string
	DefaultFeatures []string
	Dependencies    map[string]CargoDep
}

// CargoDep represents a single dependency entry from Cargo.toml.
type CargoDep struct {
	Version  string
	Features []string
	Optional bool
}

// cargoTomlFile is the raw TOML structure of a Cargo.toml file.
type cargoTomlFile struct {
	Features     map[string][]string `toml:"features"`
	Dependencies map[string]any      `toml:"dependencies"`
}

// ParseCargoToml reads and parses the Cargo.toml in sourceDir.
func ParseCargoToml(sourceDir string) (*CargoMetadata, error) {
	path := filepath.Join(sourceDir, "Cargo.toml")
	data, err := os.ReadFile(path) //nolint:gosec // path built from sourceDir + constant filename
	if err != nil {
		return nil, fmt.Errorf("read Cargo.toml: %w", err)
	}

	var raw cargoTomlFile
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse Cargo.toml: %w", err)
	}

	meta := &CargoMetadata{
		Features:     make(map[string][]string),
		Dependencies: make(map[string]CargoDep),
	}

	for name, deps := range raw.Features {
		if name == "default" {
			meta.DefaultFeatures = deps
			continue
		}
		meta.Features[name] = deps
	}

	for name, val := range raw.Dependencies {
		meta.Dependencies[name] = parseDependencyEntry(val)
	}

	return meta, nil
}

// parseDependencyEntry converts a raw TOML dependency value into a CargoDep.
func parseDependencyEntry(val any) CargoDep {
	if s, ok := val.(string); ok {
		return CargoDep{Version: s}
	}
	table, ok := val.(map[string]any)
	if !ok {
		return CargoDep{}
	}
	dep := CargoDep{}
	if ver, ok := table["version"].(string); ok {
		dep.Version = ver
	}
	if opt, ok := table["optional"].(bool); ok {
		dep.Optional = opt
	}
	dep.Features = parseStringSlice(table["features"])
	return dep
}

// parseStringSlice extracts a []string from a TOML array value.
func parseStringSlice(val any) []string {
	items, ok := val.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// IsFeatureEnabled checks whether a feature is listed in the default features
// or is always-on (non-optional dependency).
func (m *CargoMetadata) IsFeatureEnabled(feature string) bool {
	// Check if it's a default feature
	for _, f := range m.DefaultFeatures {
		if f == feature {
			return true
		}
	}
	// Check if it's an explicit feature in the features table
	_, exists := m.Features[feature]
	return exists
}

// IsDependencyEnabled checks whether a named dependency is enabled.
// Non-optional dependencies are always enabled. Optional dependencies are enabled
// only if they appear in the default features or another enabled feature references them.
func (m *CargoMetadata) IsDependencyEnabled(name string) bool {
	dep, exists := m.Dependencies[name]
	if !exists {
		return false
	}
	if !dep.Optional {
		return true
	}
	return m.isActivatedByDefaults(name)
}

// isActivatedByDefaults checks whether an optional dependency is activated
// by default features, either directly or via "dep:name" syntax.
func (m *CargoMetadata) isActivatedByDefaults(name string) bool {
	for _, f := range m.DefaultFeatures {
		if f == name {
			return true
		}
		for _, fd := range m.Features[f] {
			if fd == name || fd == "dep:"+name {
				return true
			}
		}
	}
	return false
}
