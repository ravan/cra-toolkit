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
// "pkg:npm/"). directDeps names the application's declared direct dependencies;
// only those that appear in the filtered set become roots. When directDeps is
// empty the function falls back to treating all filtered packages as roots.
func buildTransitiveSummary(components []formats.Component, directDeps []string, ecosystem string) *transitive.SBOMSummary {
	prefix := "pkg:" + ecosystem + "/"
	pkgs := make([]transitive.Package, 0, len(components))
	pkgNameSet := make(map[string]bool)

	for i := range components {
		if !strings.HasPrefix(components[i].PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, transitive.Package{
			Name:    components[i].Name,
			Version: components[i].Version,
		})
		pkgNameSet[components[i].Name] = true
	}

	// Build roots from declared direct deps intersected with the ecosystem set.
	var roots []string
	for _, dep := range directDeps {
		if pkgNameSet[dep] {
			roots = append(roots, dep)
		}
	}
	// Fallback: all ecosystem packages are roots when no direct deps are known.
	if len(roots) == 0 {
		for _, p := range pkgs {
			roots = append(roots, p.Name)
		}
	}

	return &transitive.SBOMSummary{
		Packages: pkgs,
		Roots:    roots,
	}
}

// buildTransitiveAnalyzer constructs a transitive.Analyzer for the given
// language. Returns nil when cfg.Enabled is false, the language is not
// registered in transitive.LanguageFor, or no fetcher is available for the
// language's ecosystem.
func buildTransitiveAnalyzer(cfg transitive.Config, language string) *transitive.Analyzer {
	if !cfg.Enabled {
		return nil
	}
	lang, err := transitive.LanguageFor(language)
	if err != nil {
		return nil
	}
	var cache *transitive.Cache
	if cfg.CacheDir != "" {
		cache = transitive.NewCache(cfg.CacheDir)
	}
	fetchers := buildFetchers(cache, lang.Ecosystem())
	if fetchers == nil {
		return nil
	}
	return &transitive.Analyzer{
		Config:   cfg,
		Fetchers: fetchers,
		Language: lang,
	}
}

// buildFetchers returns a map containing the single fetcher required for
// the given ecosystem, or nil if the ecosystem has no registered fetcher.
// This is the one remaining ecosystem switch in the codebase; each
// language's LanguageSupport declares the ecosystem key it requires.
func buildFetchers(cache *transitive.Cache, ecosystem string) map[string]transitive.Fetcher {
	switch ecosystem {
	case "pypi":
		return map[string]transitive.Fetcher{"pypi": &transitive.PyPIFetcher{Cache: cache}}
	case "npm":
		return map[string]transitive.Fetcher{"npm": &transitive.NPMFetcher{Cache: cache}}
	case "crates.io":
		return map[string]transitive.Fetcher{"crates.io": &transitive.CratesFetcher{Cache: cache}}
	case "rubygems":
		return map[string]transitive.Fetcher{"rubygems": &transitive.RubyGemsFetcher{Cache: cache}}
	case "packagist":
		return map[string]transitive.Fetcher{"packagist": &transitive.PackagistFetcher{Cache: cache}}
	}
	return nil
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
