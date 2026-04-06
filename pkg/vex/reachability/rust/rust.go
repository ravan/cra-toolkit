// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust implements a tree-sitter-based reachability analyzer for Rust.
package rust

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	rustgrammar "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
	rustextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/rust"
)

// Analyzer performs Rust reachability analysis using tree-sitter AST parsing.
type Analyzer struct{}

// New returns a new Rust tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "rust".
func (a *Analyzer) Language() string { return "rust" }

// crateImportName maps Cargo crate names to Rust import names.
// Hyphens become underscores by default; this map covers exceptions and common crates.
var crateImportName = map[string]string{
	"actix-web":  "actix_web",
	"async-std":  "async_std",
	"tower-http": "tower_http",
	"native-tls": "native_tls",
	"quick-xml":  "quick_xml",
	"xml-rs":     "xml",
}

// fileInfo holds per-file parse and extraction results.
type fileInfo struct {
	pr      treesitter.ParseResult
	symbols []*treesitter.Symbol
	imports []treesitter.Import
	scope   *treesitter.Scope
}

// Analyze parses all Rust files in sourceDir, builds a call graph, and checks
// whether any of the vulnerable symbols from the finding are reachable from an entry point.
//
//nolint:gocognit,gocyclo,maintidx // pipeline has multiple orchestration phases; extracting further would reduce readability
func (a *Analyzer) Analyze(_ context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Phase 1: Collect all .rs files, skipping target/
	var rustFiles []string
	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "target" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".rs") {
			rustFiles = append(rustFiles, path)
		}
		return nil
	}); err != nil {
		return reachability.Result{}, fmt.Errorf("walk %s: %w", sourceDir, err)
	}

	if len(rustFiles) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "no Rust source files found in " + sourceDir,
		}, nil
	}

	// Phase 2: Parse all files
	parseResults, parseErrs := treesitter.ParseFiles(rustFiles, rustgrammar.Language())
	parseErrCount := len(parseErrs)
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	ext := rustextractor.New()

	// Phase 3: Extract all symbols and imports from ALL files first.
	// This builds the trait-impl table across all files before ExtractCalls runs.
	fileInfos := make([]fileInfo, 0, len(parseResults))

	for _, pr := range parseResults {
		symbols, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		imports, err := ext.ResolveImports(pr.File, pr.Source, pr.Tree, sourceDir)
		if err != nil {
			continue
		}

		// Build file scope from imports
		scope := treesitter.NewScope(nil)
		for _, imp := range imports {
			alias := imp.Alias
			if alias == "" {
				alias = imp.Module
			}
			scope.DefineImport(alias, imp.Module, imp.Symbols)
		}

		fileInfos = append(fileInfos, fileInfo{
			pr:      pr,
			symbols: symbols,
			imports: imports,
			scope:   scope,
		})
	}

	// Snapshot the accumulated trait-impl state before Phase 4 resets it per-file.
	traitSnapshot := ext.SnapshotTraitImpls()

	// Build the call graph — add all known symbols first
	graph := treesitter.NewGraph()
	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			graph.AddSymbol(sym)
		}
	}

	// Phase 4: Extract calls and add edges.
	// Re-run ExtractSymbols to restore per-file state, then merge back snapshot.
	for _, fi := range fileInfos {
		if _, err := ext.ExtractSymbols(fi.pr.File, fi.pr.Source, fi.pr.Tree); err != nil {
			continue
		}
		ext.RestoreTraitImpls(traitSnapshot)

		edges, err := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, fi.scope)
		if err != nil {
			continue
		}

		for _, e := range edges {
			graph.AddEdge(e)
		}
	}

	// Phase 5: Find entry points
	allSymbols := graph.AllSymbols()
	entryPoints := ext.FindEntryPoints(allSymbols, sourceDir)

	if len(entryPoints) == 0 {
		// Fall back: treat all functions as entry points
		for _, sym := range allSymbols {
			if sym.Kind == treesitter.SymbolFunction || sym.Kind == treesitter.SymbolMethod {
				entryPoints = append(entryPoints, sym.ID)
			}
		}
	}

	// Mark entry points in the graph
	for _, ep := range entryPoints {
		sym := graph.GetSymbol(ep)
		if sym != nil {
			sym.IsEntryPoint = true
		}
	}

	// Phase 6: Build target symbol IDs from the finding and BFS to them
	targets := buildTargetIDs(finding.AffectedName, finding.Symbols)

	// Add targets as virtual nodes so BFS can find them
	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "rust",
			})
		}
	}

	// BFS reachability from entry points to each target
	var allPaths []reachability.CallPath
	var reachedSymbols []string

	cfg := treesitter.ReachabilityConfig{MaxDepth: 20, MaxPaths: 5}
	for _, targetID := range targets {
		paths := treesitter.FindReachablePaths(graph, entryPoints, targetID, cfg)
		if len(paths) > 0 {
			allPaths = append(allPaths, paths...)
			reachedSymbols = append(reachedSymbols, string(targetID))
		}
	}

	parseErrSuffix := ""
	if parseErrCount > 0 {
		parseErrSuffix = fmt.Sprintf(" (%d file(s) skipped due to parse errors)", parseErrCount)
	}

	if len(allPaths) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   fmt.Sprintf("tree-sitter analysis found no call path to {%s}%s", strings.Join(finding.Symbols, ","), parseErrSuffix),
		}, nil
	}

	evidence := fmt.Sprintf("tree-sitter call graph: %s is reachable via %d path(s): %s%s",
		strings.Join(reachedSymbols, ", "),
		len(allPaths),
		allPaths[0].String(),
		parseErrSuffix,
	)

	return reachability.Result{
		Reachable:  true,
		Confidence: formats.ConfidenceHigh,
		Evidence:   evidence,
		Symbols:    reachedSymbols,
		Paths:      allPaths,
	}, nil
}

// crateToImportName converts a Cargo crate name to the Rust import name.
// Uses the explicit mapping if available, otherwise converts hyphens to underscores.
func crateToImportName(crateName string) string {
	if name, ok := crateImportName[crateName]; ok {
		return name
	}
	return strings.ReplaceAll(crateName, "-", "_")
}

// buildTargetIDs creates SymbolIDs for the vulnerable symbols.
//
// For Rust, finding.Symbols may be:
//   - Already qualified: "hyper::server::conn::Http.http2_only" → normalize :: to . and use as-is
//   - Simple method names: "http2_only" → prefix with import name (e.g. "hyper.http2_only")
//     and also add the bare method name for unqualified matches
func buildTargetIDs(crateName string, symbols []string) []treesitter.SymbolID {
	importName := crateToImportName(crateName)
	seen := make(map[treesitter.SymbolID]bool)
	var ids []treesitter.SymbolID

	add := func(id treesitter.SymbolID) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	for _, sym := range symbols {
		if strings.Contains(sym, ".") || strings.Contains(sym, "::") {
			// Already qualified — normalize :: to .
			normalized := strings.ReplaceAll(sym, "::", ".")
			add(treesitter.SymbolID(normalized))
		} else {
			// Simple name — add prefixed version and bare version
			add(treesitter.SymbolID(importName + "." + sym))
			// Also try bare method name for method calls like obj.http2_only()
			add(treesitter.SymbolID(sym))
			// Also try ".method" form for chained calls where the receiver is
			// a complex expression (e.g. Http::new().http2_only(true)), which the
			// extractor emits as ".http2_only" (empty receiver + "." + method).
			add(treesitter.SymbolID("." + sym))
		}
	}

	return ids
}
