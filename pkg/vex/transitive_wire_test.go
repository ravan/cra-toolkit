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
	summary := buildTransitiveSummary(testComponents(), "pypi")
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
	summary := buildTransitiveSummary(testComponents(), "npm")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Packages) != 2 {
		t.Errorf("expected 2 npm packages, got %d", len(summary.Packages))
	}
}

func TestBuildTransitiveSummary_UnknownEcosystem(t *testing.T) {
	summary := buildTransitiveSummary(testComponents(), "cargo")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Packages) != 0 {
		t.Errorf("expected 0 packages for unknown ecosystem, got %d", len(summary.Packages))
	}
}

func TestBuildTransitiveSummary_NilComponents(t *testing.T) {
	summary := buildTransitiveSummary(nil, "pypi")
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
	summary := buildTransitiveSummary(components, "pypi")
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(summary.Roots) == 0 {
		t.Error("expected at least one root package")
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
	if a.Language != "python" {
		t.Errorf("Language: got %q, want %q", a.Language, "python")
	}
	if a.Ecosystem != "pypi" {
		t.Errorf("Ecosystem: got %q, want %q", a.Ecosystem, "pypi")
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
	if a.Language != "javascript" {
		t.Errorf("Language: got %q, want %q", a.Language, "javascript")
	}
	if a.Ecosystem != "npm" {
		t.Errorf("Ecosystem: got %q, want %q", a.Ecosystem, "npm")
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
