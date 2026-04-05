// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package php implements a tree-sitter-based reachability analyzer for PHP.
package php

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	phpgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/php"
	phpextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/php"
)

// Analyzer performs PHP reachability analysis using tree-sitter AST parsing.
type Analyzer struct{}

// New returns a new PHP tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "php".
func (a *Analyzer) Language() string { return "php" }

// composerAutoload holds PSR-4 autoload mappings from composer.json.
type composerAutoload struct {
	Autoload struct {
		PSR4 map[string]string `json:"psr-4"`
	} `json:"autoload"`
}

// fileInfo holds per-file parse and extraction results.
type fileInfo struct {
	pr      treesitter.ParseResult
	symbols []*treesitter.Symbol
	imports []treesitter.Import
	scope   *treesitter.Scope
}

// Analyze parses all PHP files in sourceDir, builds a call graph, and checks
// whether any of the vulnerable symbols from the finding are reachable from an entry point.
//
//nolint:gocognit,gocyclo,maintidx // pipeline has multiple orchestration phases; extracting further would reduce readability
func (a *Analyzer) Analyze(_ context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Collect all PHP files via WalkDir
	var phpFiles []string
	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".php") {
			phpFiles = append(phpFiles, path)
		}
		return nil
	}); err != nil {
		return reachability.Result{}, fmt.Errorf("walk %s: %w", sourceDir, err)
	}

	if len(phpFiles) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "no PHP source files found in " + sourceDir,
		}, nil
	}

	// Parse composer.json for PSR-4 autoload mappings (namespace → directory)
	namespaceMap := loadComposerAutoload(sourceDir)

	// Parse all files
	parseResults, parseErrs := treesitter.ParseFiles(phpFiles, phpgrammar.Language())
	parseErrCount := len(parseErrs)
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	ext := phpextractor.New()

	// Phase 1: Extract all symbols and imports from ALL files.
	// For PHP, ExtractSymbols resets per-file attribute/modifier state each call.
	// We therefore collect entry points immediately after ExtractSymbols for each file,
	// before the state is overwritten by the next file.
	fileInfos := make([]fileInfo, 0, len(parseResults))
	var entryPoints []treesitter.SymbolID

	for _, pr := range parseResults {
		symbols, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		imports, err := ext.ResolveImports(pr.File, pr.Source, pr.Tree, sourceDir)
		if err != nil {
			continue
		}

		// Collect entry points for this file while extractor state is fresh.
		fileEPs := ext.FindEntryPoints(symbols, sourceDir)
		entryPoints = append(entryPoints, fileEPs...)

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

	// Phase 2: Build the call graph and add all known symbols.
	graph := treesitter.NewGraph()

	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			graph.AddSymbol(sym)
		}
	}

	// Phase 3: Extract calls and add edges.
	for _, fi := range fileInfos {
		edges, err := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, fi.scope)
		if err != nil {
			continue
		}
		for _, e := range edges {
			graph.AddEdge(e)
		}
	}

	// Phase 4: Finalize entry points.
	allSymbols := graph.AllSymbols()

	if len(entryPoints) == 0 {
		// Fall back: treat all methods as entry points
		for _, sym := range allSymbols {
			if sym.Kind == treesitter.SymbolMethod {
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

	// Phase 5: Build target symbol IDs from the finding.
	targets := buildTargetIDs(finding.AffectedName, finding.Symbols, namespaceMap)

	// Add targets as virtual nodes in the graph so BFS can find them
	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "php",
			})
		}
	}

	// Phase 6: BFS reachability from entry points to each target
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

// loadComposerAutoload reads composer.json from sourceDir and returns PSR-4 namespace→path mappings.
func loadComposerAutoload(sourceDir string) map[string]string {
	composerPath := filepath.Join(sourceDir, "composer.json")
	data, err := os.ReadFile(composerPath) //nolint:gosec // path is constructed from sourceDir, not user-controlled
	if err != nil {
		return nil
	}
	var cfg composerAutoload
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return cfg.Autoload.PSR4
}

// buildTargetIDs creates SymbolIDs for the vulnerable symbols.
//
// For PHP, finding.Symbols may be:
//   - Fully qualified: "GuzzleHttp\Client::get" → used as-is for member call matching
//   - Short form: "Client::get" → used as-is, may also be qualified with namespace from composer
//
// The extractor emits edges with targets like "client::get" (variable name) or "Client::get" (class name).
// We generate multiple candidate IDs to match various forms.
func buildTargetIDs(artifactName string, symbols []string, _ map[string]string) []treesitter.SymbolID {
	ids := make([]treesitter.SymbolID, 0, len(symbols)*3)
	for _, sym := range symbols {
		// Add as-is
		ids = append(ids, treesitter.SymbolID(sym))

		// If the symbol contains a namespace separator, also add the short form
		// e.g. "GuzzleHttp\Client::get" → also add "Client::get"
		if backslash := strings.LastIndex(sym, `\`); backslash >= 0 {
			short := sym[backslash+1:]
			ids = append(ids, treesitter.SymbolID(short))
		}

		// If the symbol contains "::", also try the variable-name version
		// e.g. "GuzzleHttp\Client::get" → "client::get" (lowercase variable name)
		if colonColon := strings.LastIndex(sym, "::"); colonColon >= 0 {
			className := sym
			if backslash := strings.LastIndex(sym, `\`); backslash >= 0 {
				className = sym[backslash+1 : colonColon]
			} else {
				className = sym[:colonColon]
			}
			methodPart := sym[colonColon+2:]
			// lowercase the first letter of the class name to match variable names
			if className != "" {
				varName := strings.ToLower(className[:1]) + className[1:]
				ids = append(ids, treesitter.SymbolID(varName+"::"+methodPart))
			}
		}
	}
	return ids
}
