// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import (
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive"
)

// testComponents returns a mixed set of components across pypi, npm, and golang.
func testComponents() []formats.Component {
	return []formats.Component{
		{Name: "flask", Version: "2.3.0", PURL: "pkg:pypi/flask@2.3.0", Type: "pypi"},
		{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0", Type: "pypi"},
		{Name: "express", Version: "4.18.2", PURL: "pkg:npm/express@4.18.2", Type: "npm"},
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Type: "npm"},
		{Name: "github.com/gin-gonic/gin", Version: "1.9.0", PURL: "pkg:golang/github.com/gin-gonic/gin@1.9.0", Type: "golang"},
	}
}

func TestBuildTransitiveSummary_PyPI(t *testing.T) {
	summary := buildTransitiveSummary(testComponents(), nil, "pypi")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Packages) != 2 {
		t.Errorf("expected 2 pypi packages, got %d", len(summary.Packages))
	}

	found := false
	for _, pkg := range summary.Packages {
		if pkg.Name == "flask" {
			found = true
			if pkg.Version != "2.3.0" {
				t.Errorf("flask version: got %q, want %q", pkg.Version, "2.3.0")
			}
			break
		}
	}
	if !found {
		t.Error("flask not found in pypi packages")
	}
}

func TestBuildTransitiveSummary_NPM(t *testing.T) {
	summary := buildTransitiveSummary(testComponents(), nil, "npm")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Packages) != 2 {
		t.Errorf("expected 2 npm packages, got %d", len(summary.Packages))
	}
}

func TestBuildTransitiveSummary_UnknownEcosystem(t *testing.T) {
	summary := buildTransitiveSummary(testComponents(), nil, "cargo")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Packages) != 0 {
		t.Errorf("expected 0 packages for unknown ecosystem, got %d", len(summary.Packages))
	}
}

func TestBuildTransitiveSummary_NilComponents(t *testing.T) {
	summary := buildTransitiveSummary(nil, nil, "pypi")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Packages) != 0 {
		t.Error("expected empty packages for nil input")
	}
}

func TestBuildTransitiveSummary_Roots(t *testing.T) {
	components := []formats.Component{
		{Name: "flask", Version: "2.3.0", PURL: "pkg:pypi/flask@2.3.0", Type: "pypi"},
		{Name: "werkzeug", Version: "2.3.0", PURL: "pkg:pypi/werkzeug@2.3.0", Type: "pypi"},
	}
	summary := buildTransitiveSummary(components, nil, "pypi")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Roots) == 0 {
		t.Error("expected at least one root package")
	}
}

func TestBuildTransitiveSummary_WithDirectDeps(t *testing.T) {
	components := []formats.Component{
		{Name: "flask", Version: "2.3.0", PURL: "pkg:pypi/flask@2.3.0", Type: "pypi"},
		{Name: "werkzeug", Version: "2.3.0", PURL: "pkg:pypi/werkzeug@2.3.0", Type: "pypi"},
	}
	// Only flask is a direct dep; werkzeug is transitive.
	summary := buildTransitiveSummary(components, []string{"flask"}, "pypi")
	if len(summary.Roots) != 1 || summary.Roots[0] != "flask" {
		t.Errorf("roots: got %v, want [flask]", summary.Roots)
	}
}

func TestBuildTransitiveSummary_DirectDepsFilteredToEcosystem(t *testing.T) {
	// directDeps may contain names from other ecosystems; only matching ones become roots.
	summary := buildTransitiveSummary(testComponents(), []string{"flask", "express"}, "pypi")
	if len(summary.Roots) != 1 || summary.Roots[0] != "flask" {
		t.Errorf("roots: got %v, want [flask]", summary.Roots)
	}
}

func TestBuildTransitiveSummary_FallbackWhenNoDirectDeps(t *testing.T) {
	components := []formats.Component{
		{Name: "flask", Version: "2.3.0", PURL: "pkg:pypi/flask@2.3.0", Type: "pypi"},
		{Name: "werkzeug", Version: "2.3.0", PURL: "pkg:pypi/werkzeug@2.3.0", Type: "pypi"},
	}
	// nil directDeps → all packages become roots (fallback).
	summary := buildTransitiveSummary(components, nil, "pypi")
	if len(summary.Roots) != 2 {
		t.Errorf("fallback roots: got %d, want 2", len(summary.Roots))
	}
}

func TestBuildTransitiveAnalyzer_Disabled(t *testing.T) {
	cfg := transitive.Config{Enabled: false}
	a := buildTransitiveAnalyzer(cfg, "python")
	if a != nil {
		t.Error("expected nil analyzer when config disabled")
	}
}

func TestBuildTransitiveAnalyzer_Python(t *testing.T) {
	cfg := transitive.DefaultConfig()
	a := buildTransitiveAnalyzer(cfg, "python")
	if a == nil {
		t.Fatal("expected non-nil analyzer for python")
	}
	if a.Language.Name() != "python" {
		t.Errorf("Language.Name(): got %q, want %q", a.Language.Name(), "python")
	}
	if a.Language.Ecosystem() != "pypi" {
		t.Errorf("Language.Ecosystem(): got %q, want %q", a.Language.Ecosystem(), "pypi")
	}
	if _, ok := a.Fetchers["pypi"]; !ok {
		t.Error("expected pypi fetcher in Fetchers map")
	}
}

func TestBuildTransitiveAnalyzer_JavaScript(t *testing.T) {
	cfg := transitive.DefaultConfig()
	a := buildTransitiveAnalyzer(cfg, "javascript")
	if a == nil {
		t.Fatal("expected non-nil analyzer for javascript")
	}
	if a.Language.Name() != "javascript" {
		t.Errorf("Language.Name(): got %q, want %q", a.Language.Name(), "javascript")
	}
	if a.Language.Ecosystem() != "npm" {
		t.Errorf("Language.Ecosystem(): got %q, want %q", a.Language.Ecosystem(), "npm")
	}
	if _, ok := a.Fetchers["npm"]; !ok {
		t.Error("expected npm fetcher in Fetchers map")
	}
}

func TestBuildTransitiveAnalyzer_UnsupportedLanguage(t *testing.T) {
	cfg := transitive.DefaultConfig()
	a := buildTransitiveAnalyzer(cfg, "go")
	if a != nil {
		t.Error("expected nil analyzer for unsupported language")
	}
}

func TestResolveTransitiveConfig_YAMLOverridesDefaults(t *testing.T) {
	rc := &ReachabilityConfig{
		Transitive: transitive.Config{
			MaxHopsPerPath: 20,
		},
	}
	opts := &Options{TransitiveEnabled: true}
	cfg := resolveTransitiveConfig(opts, rc)
	if cfg.MaxHopsPerPath != 20 {
		t.Errorf("expected MaxHopsPerPath=20, got %d", cfg.MaxHopsPerPath)
	}
	defaults := transitive.DefaultConfig()
	if cfg.MaxPathsPerFinding != defaults.MaxPathsPerFinding {
		t.Errorf("default MaxPathsPerFinding lost, got %d", cfg.MaxPathsPerFinding)
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestResolveTransitiveConfig_CLIOverridesYAML(t *testing.T) {
	rc := &ReachabilityConfig{
		Transitive: transitive.Config{
			CacheDir: "/from/yaml",
		},
	}
	opts := &Options{TransitiveEnabled: true, TransitiveCacheDir: "/from/cli"}
	cfg := resolveTransitiveConfig(opts, rc)
	if cfg.CacheDir != "/from/cli" {
		t.Errorf("expected CLI cache dir /from/cli, got %q", cfg.CacheDir)
	}
}

func TestResolveTransitiveConfig_CLIEnabledWinsOverYAML(t *testing.T) {
	rc := &ReachabilityConfig{
		Transitive: transitive.Config{Enabled: false},
	}
	opts := &Options{TransitiveEnabled: true}
	cfg := resolveTransitiveConfig(opts, rc)
	if !cfg.Enabled {
		t.Error("opts.TransitiveEnabled must win over YAML Enabled field")
	}
}

func TestResolveTransitiveConfig_DisabledViaOpts(t *testing.T) {
	opts := &Options{TransitiveEnabled: false}
	cfg := resolveTransitiveConfig(opts, nil)
	if cfg.Enabled {
		t.Error("expected Enabled=false when opts.TransitiveEnabled=false")
	}
	defaults := transitive.DefaultConfig()
	if cfg.MaxPathsPerFinding != defaults.MaxPathsPerFinding {
		t.Errorf("default MaxPathsPerFinding lost, got %d", cfg.MaxPathsPerFinding)
	}
}

func TestBuildFetchers_CratesIO(t *testing.T) {
	cache := transitive.NewCache(t.TempDir())
	fetchers := buildFetchers(cache, "crates.io")
	if fetchers == nil {
		t.Fatal("buildFetchers(crates.io) returned nil")
	}
	f, ok := fetchers["crates.io"]
	if !ok {
		t.Fatal("fetchers missing crates.io key")
	}
	if _, ok := f.(*transitive.CratesFetcher); !ok {
		t.Errorf("fetchers[crates.io] is %T, want *transitive.CratesFetcher", f)
	}
}
