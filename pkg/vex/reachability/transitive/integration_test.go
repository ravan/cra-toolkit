// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build integration

package transitive

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

type expectedFixture struct {
	Description string `json:"description"`
	Findings    []struct {
		CVE                string `json:"cve"`
		ComponentPURL      string `json:"component_purl"`
		ExpectedStatus     string `json:"expected_status"`
		ExpectedResolvedBy string `json:"expected_resolved_by"`
	} `json:"findings"`
}

func loadFixture(t *testing.T, dir string) expectedFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var f expectedFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return f
}

type cdxComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type cdxDoc struct {
	Components []cdxComponent `json:"components"`
}

func parseSBOMForTest(t *testing.T, path, ecosystem string) *SBOMSummary {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc cdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal sbom: %v", err)
	}
	prefix := "pkg:" + ecosystem + "/"
	var pkgs []Package
	for _, c := range doc.Components {
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, Package{Name: c.Name, Version: c.Version})
	}
	if len(pkgs) == 0 {
		t.Fatalf("no %s components in sbom %s", ecosystem, path)
	}
	roots := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		roots = append(roots, p.Name)
	}
	return &SBOMSummary{Packages: pkgs, Roots: roots}
}

func runIntegrationFixture(t *testing.T, fixtureDir, language, ecosystem, affectedName, affectedVersion string, wantReachable bool) {
	t.Helper()
	fx := loadFixture(t, fixtureDir)
	if len(fx.Findings) == 0 {
		t.Fatal("fixture has no findings")
	}

	summary := parseSBOMForTest(t, filepath.Join(fixtureDir, "sbom.cdx.json"), ecosystem)
	cache := NewCache(t.TempDir())

	var fetcher Fetcher
	switch ecosystem {
	case "pypi":
		fetcher = &PyPIFetcher{Cache: cache}
	case "npm":
		fetcher = &NPMFetcher{Cache: cache}
	default:
		t.Fatalf("unknown ecosystem %q", ecosystem)
	}

	analyzer := &Analyzer{
		Config:    DefaultConfig(),
		Language:  language,
		Ecosystem: ecosystem,
		Fetchers:  map[string]Fetcher{ecosystem: fetcher},
	}

	res, err := analyzer.Analyze(context.Background(), summary, &formats.Finding{
		AffectedName:    affectedName,
		AffectedVersion: affectedVersion,
	}, filepath.Join(fixtureDir, "source"))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if res.Reachable != wantReachable {
		t.Errorf("reachable: want %v, got %v\nevidence: %s\ndegradations: %v",
			wantReachable, res.Reachable, res.Evidence, res.Degradations)
	}
	if wantReachable && len(res.Paths) == 0 {
		t.Errorf("expected at least one stitched call path, got none")
	}
}

func TestIntegration_Transitive_PythonReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "python-realworld-cross-package")
	runIntegrationFixture(t, dir, "python", "pypi", "urllib3", "2.0.5", true)
}

func TestIntegration_Transitive_PythonNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "python-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "python", "pypi", "urllib3", "2.0.5", false)
}

func TestIntegration_Transitive_JavaScriptReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "javascript-realworld-cross-package")
	runIntegrationFixture(t, dir, "javascript", "npm", "follow-redirects", "1.14.0", true)
}

func TestIntegration_Transitive_JavaScriptNotReachable(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "..", "testdata", "integration", "javascript-realworld-cross-package-safe")
	runIntegrationFixture(t, dir, "javascript", "npm", "follow-redirects", "1.14.0", false)
}
