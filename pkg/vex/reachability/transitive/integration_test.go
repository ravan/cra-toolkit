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
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxDoc struct {
	Metadata struct {
		Component struct {
			BOMRef string `json:"bom-ref"`
		} `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
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

	// Build bom-ref → name map and collect ecosystem packages.
	refToName := make(map[string]string)
	var pkgs []Package
	pkgNameSet := make(map[string]bool)
	for _, c := range doc.Components {
		if c.BOMRef != "" {
			refToName[c.BOMRef] = c.Name
		}
		if !strings.HasPrefix(c.PURL, prefix) {
			continue
		}
		pkgs = append(pkgs, Package{Name: c.Name, Version: c.Version})
		pkgNameSet[c.Name] = true
	}
	if len(pkgs) == 0 {
		t.Fatalf("no %s components in sbom %s", ecosystem, path)
	}

	// Derive roots from the metadata application component's dependsOn.
	appRef := doc.Metadata.Component.BOMRef
	var roots []string
	if appRef != "" {
		for _, dep := range doc.Dependencies {
			if dep.Ref != appRef {
				continue
			}
			for _, childRef := range dep.DependsOn {
				name := sbomRefName(childRef, refToName)
				if pkgNameSet[name] {
					roots = append(roots, name)
				}
			}
			break
		}
	}
	if len(roots) == 0 {
		t.Logf("SBOM %s: no application-level dependsOn found — using all %s packages as roots (degraded)", path, ecosystem)
		for _, p := range pkgs {
			roots = append(roots, p.Name)
		}
	}

	return &SBOMSummary{Packages: pkgs, Roots: roots}
}

// sbomRefName resolves a CycloneDX dependency ref to a package name.
// Tries the bom-ref map first, then extracts from PURL:
// "pkg:pypi/requests@2.31.0?package-id=abc" → "requests"
func sbomRefName(ref string, refToName map[string]string) string {
	if n, ok := refToName[ref]; ok {
		return n
	}
	// PURL: "pkg:<type>/<name>@<version>[?qualifiers]"
	// Find the last "/" before "@" or "?"
	slashIdx := strings.LastIndex(ref, "/")
	if slashIdx < 0 {
		return ""
	}
	nameVer := ref[slashIdx+1:]
	if atIdx := strings.IndexByte(nameVer, '@'); atIdx >= 0 {
		return nameVer[:atIdx]
	}
	if qIdx := strings.IndexByte(nameVer, '?'); qIdx >= 0 {
		return nameVer[:qIdx]
	}
	return nameVer
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
