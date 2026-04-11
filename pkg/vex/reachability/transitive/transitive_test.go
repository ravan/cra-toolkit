// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"testing"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/python"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/transitive/languages/rust"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

func TestAnalyzer_NotApplicable_WhenNoSBOM(t *testing.T) {
	a := &Analyzer{Config: DefaultConfig()}
	res, err := a.Analyze(context.Background(), nil, &formats.Finding{AffectedName: "urllib3"}, "/app")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Degradations) == 0 || res.Degradations[0] != ReasonTransitiveNotApplicable {
		t.Errorf("expected transitive_not_applicable, got %v", res.Degradations)
	}
}

func TestAnalyzer_NotApplicable_WhenPackageNotInGraph(t *testing.T) {
	// fakeFetcher is declared in sbom_graph_test.go (same package).
	sbom := &SBOMSummary{
		Packages: []Package{{Name: "flask", Version: "2.0.1"}},
		Roots:    []string{"flask"},
	}
	a := &Analyzer{
		Config: DefaultConfig(),
		Fetchers: map[string]Fetcher{"pypi": &fakeFetcher{
			eco:       "pypi",
			manifests: map[string]map[string]string{"flask@2.0.1": {}},
		}},
		Language: python.New(),
	}
	res, err := a.Analyze(context.Background(), sbom, &formats.Finding{AffectedName: "unknown"}, "/app")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Degradations) == 0 || res.Degradations[0] != ReasonTransitiveNotApplicable {
		t.Errorf("expected transitive_not_applicable, got %v", res.Degradations)
	}
}

func TestCollectVulnSymbols_NoLibraryAPI(t *testing.T) {
	lang := &noLibAPILang{}
	a := &Analyzer{
		Config:   DefaultConfig(),
		Language: lang,
		Fetchers: map[string]Fetcher{"crates.io": &noLibAPIFetcher{}},
	}
	_, degradations := a.collectVulnSymbols(context.Background(), &formats.Finding{
		AffectedName:    "mycrate",
		AffectedVersion: "0.1.0",
	})
	for _, d := range degradations {
		if d == ReasonNoLibraryAPI {
			return
		}
	}
	t.Errorf("degradations = %v, want to contain %q", degradations, ReasonNoLibraryAPI)
}

type noLibAPILang struct{}

func (noLibAPILang) Name() string                             { return "rust" }
func (noLibAPILang) Ecosystem() string                        { return "crates.io" }
func (noLibAPILang) FileExtensions() []string                 { return []string{".rs"} }
func (noLibAPILang) Grammar() unsafe.Pointer                  { return nil }
func (noLibAPILang) Extractor() treesitter.LanguageExtractor  { return nil }
func (noLibAPILang) IsExportedSymbol(*treesitter.Symbol) bool { return false }
func (noLibAPILang) ModulePath(string, string, string) string { return "" }
func (noLibAPILang) SymbolKey(string, string) string          { return "" }
func (noLibAPILang) NormalizeImports(raw []treesitter.Import) []treesitter.Import {
	return raw
}

func (noLibAPILang) ResolveDottedTarget(string, string, *treesitter.Scope) (treesitter.SymbolID, bool) {
	return "", false
}

func (noLibAPILang) ResolveSelfCall(to, _ treesitter.SymbolID) treesitter.SymbolID {
	return to
}

func (noLibAPILang) ListExports(string, string) ([]string, error) {
	return nil, rust.ErrNoLibraryAPI
}

type noLibAPIFetcher struct{}

func (noLibAPIFetcher) Ecosystem() string { return "crates.io" }
func (noLibAPIFetcher) Fetch(_ context.Context, _, _ string, _ *Digest) (FetchResult, error) {
	return FetchResult{SourceDir: "/tmp/fake"}, nil
}

func (noLibAPIFetcher) Manifest(_ context.Context, _, _ string) (PackageManifest, error) {
	return PackageManifest{}, nil
}
