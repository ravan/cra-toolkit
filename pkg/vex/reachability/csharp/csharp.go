// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package csharp implements a tree-sitter-based reachability analyzer for C#.
package csharp

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	csharpextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/csharp"
	csharpgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/csharp"
)

// Analyzer performs C# reachability analysis using tree-sitter AST parsing.
type Analyzer struct{}

// New returns a new C# tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "csharp".
func (a *Analyzer) Language() string { return "csharp" }

// nugetNamespacePrefix maps NuGet package names → root C# namespace prefix.
// Used to qualify short symbol names (e.g. "DeserializeObject") into full call targets.
// Findings that already include the class qualifier (e.g. "JsonConvert.DeserializeObject")
// are used as-is and do not need this mapping.
var nugetNamespacePrefix = map[string]string{
	"Newtonsoft.Json":              "Newtonsoft.Json",
	"Microsoft.AspNetCore.Mvc":     "Microsoft.AspNetCore.Mvc",
	"Microsoft.Extensions.Hosting": "Microsoft.Extensions.Hosting",
	"Serilog":                      "Serilog",
	"log4net":                      "log4net",
	"NLog":                         "NLog",
}

// fileInfo holds per-file parse and extraction results.
type fileInfo struct {
	pr      treesitter.ParseResult
	symbols []*treesitter.Symbol
	imports []treesitter.Import
	scope   *treesitter.Scope
}

// Analyze parses all C# files in sourceDir, builds a call graph, and checks
// whether any of the vulnerable symbols from the finding are reachable from an entry point.
//
//nolint:gocognit,gocyclo,maintidx // pipeline has multiple orchestration phases; extracting further would reduce readability
func (a *Analyzer) Analyze(_ context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Collect all C# files via WalkDir
	var csFiles []string
	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".cs") {
			csFiles = append(csFiles, path)
		}
		return nil
	}); err != nil {
		return reachability.Result{}, fmt.Errorf("walk %s: %w", sourceDir, err)
	}

	if len(csFiles) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "no C# source files found in " + sourceDir,
		}, nil
	}

	// Parse all files
	parseResults, parseErrs := treesitter.ParseFiles(csFiles, csharpgrammar.Language())
	parseErrCount := len(parseErrs)
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	ext := csharpextractor.New()

	// Phase 1: Extract all symbols and imports from ALL files.
	// For C#, ExtractSymbols resets per-file attribute/modifier state each call.
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
	targets := buildTargetIDs(finding.AffectedName, finding.Symbols)

	// Add targets as virtual nodes in the graph so BFS can find them
	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "csharp",
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

// buildTargetIDs creates SymbolIDs for the vulnerable symbols.
//
// For C#, finding.Symbols may be:
//   - Qualified call targets like "JsonConvert.DeserializeObject" → used as-is,
//     since the extractor emits edges with target "JsonConvert.DeserializeObject"
//     when it sees JsonConvert.DeserializeObject(...) in the source.
//   - Simple method names like "DeserializeObject" → prefixed with NuGet namespace prefix.
func buildTargetIDs(artifactName string, symbols []string) []treesitter.SymbolID {
	ids := make([]treesitter.SymbolID, 0, len(symbols))
	for _, sym := range symbols {
		if strings.Contains(sym, ".") {
			// Already qualified (e.g. "JsonConvert.DeserializeObject")
			ids = append(ids, treesitter.SymbolID(sym))
		} else {
			// Simple name — try to qualify with NuGet namespace prefix
			if prefix, ok := nugetNamespacePrefix[artifactName]; ok {
				ids = append(ids, treesitter.SymbolID(prefix+"."+sym))
			} else {
				// Fall back: use as-is
				ids = append(ids, treesitter.SymbolID(sym))
			}
		}
	}
	return ids
}
