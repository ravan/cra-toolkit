// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import (
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

// buildTransitiveSummary projects a flat []formats.Component slice into the
// minimal SBOMSummary the transitive analyzer needs. Components are filtered to
// those whose PURL starts with "pkg:<ecosystem>/" (e.g. "pkg:pypi/" or
// "pkg:npm/"). All matching packages are also treated as potential roots because
// the SBOM component list does not reliably distinguish direct vs. transitive
// dependencies at this layer.
func buildTransitiveSummary(components []formats.Component, ecosystem string) *transitive.SBOMSummary {
	prefix := "pkg:" + ecosystem + "/"
	pkgs := make([]transitive.Package, 0, len(components))
	roots := make([]string, 0, len(components))

	for i := range components {
		if !strings.HasPrefix(components[i].PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{
			Name:    components[i].Name,
			Version: components[i].Version,
		})
		roots = append(roots, components[i].Name)
	}

	return &transitive.SBOMSummary{
		Packages: pkgs,
		Roots:    roots,
	}
}

// buildTransitiveAnalyzer constructs a transitive.Analyzer for the given language.
// Returns nil when cfg.Enabled is false or the language is not supported
// (currently "python" and "javascript" only).
func buildTransitiveAnalyzer(cfg transitive.Config, language string) *transitive.Analyzer {
	if !cfg.Enabled {
		return nil
	}

	var ecosystem string
	switch language {
	case "python":
		ecosystem = "pypi"
	case "javascript":
		ecosystem = "npm"
	default:
		return nil
	}

	var cache *transitive.Cache
	if cfg.CacheDir != "" {
		cache = transitive.NewCache(cfg.CacheDir)
	}

	var fetcher transitive.Fetcher
	switch ecosystem {
	case "pypi":
		fetcher = &transitive.PyPIFetcher{Cache: cache}
	case "npm":
		fetcher = &transitive.NPMFetcher{Cache: cache}
	}

	return &transitive.Analyzer{
		Config:    cfg,
		Fetchers:  map[string]transitive.Fetcher{ecosystem: fetcher},
		Language:  language,
		Ecosystem: ecosystem,
	}
}

// ReachabilityConfig holds YAML-configurable bounds for reachability analysis.
// It is embedded in whatever top-level product-config struct is added later.
type ReachabilityConfig struct {
	Transitive transitive.Config `yaml:"transitive,omitempty"`
}

// resolveTransitiveConfig returns the transitive Config to use for a vex.Run.
// It starts from DefaultConfig, merges any YAML-provided ReachabilityConfig,
// then applies CLI-level overrides from opts (which always win).
func resolveTransitiveConfig(opts *Options, rc *ReachabilityConfig) transitive.Config {
	cfg := transitive.DefaultConfig()
	if rc != nil {
		cfg = cfg.Merge(rc.Transitive)
	}
	cfg.Enabled = opts.TransitiveEnabled
	if opts.TransitiveCacheDir != "" {
		cfg.CacheDir = opts.TransitiveCacheDir
	}
	return cfg
}
