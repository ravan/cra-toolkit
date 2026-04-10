// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjs "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	jsextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/javascript"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// HopInput describes a single per-hop reachability query.
type HopInput struct {
	// Language is the source language: "python" or "javascript".
	Language string
	// SourceDir is the root directory containing source files to scan.
	SourceDir string
	// TargetSymbols are the qualified symbol names to search for
	// (e.g. "urllib3.PoolManager", "lodash.merge").
	TargetSymbols []string
	// MaxTargets caps how many TargetSymbols are processed.
	MaxTargets int
}

// HopResult holds the outcome of a per-hop reachability query.
type HopResult struct {
	// ReachingSymbols are the qualified names of local symbols that can
	// directly or transitively call at least one of the TargetSymbols.
	ReachingSymbols []string
}

// RunHop parses the source files in input.SourceDir, builds a call graph,
// injects the TargetSymbols as virtual external nodes, and returns the set
// of local symbols that can transitively reach any target symbol.
//
//nolint:gocognit,gocyclo,maintidx // multi-phase call graph pipeline; splitting further would obscure the flow
func RunHop(_ context.Context, input HopInput) (HopResult, error) {
	ext, langPtr, fileExt, err := extractorForLanguage(input.Language)
	if err != nil {
		return HopResult{}, err
	}

	// Collect all source files.
	var files []string
	if walkErr := filepath.WalkDir(input.SourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(path, fileExt) {
			files = append(files, path)
		}
		return nil
	}); walkErr != nil {
		return HopResult{}, fmt.Errorf("walk %s: %w", input.SourceDir, walkErr)
	}

	if len(files) == 0 {
		return HopResult{}, nil
	}

	// Parse all files concurrently.
	parseResults, _ := treesitter.ParseFiles(files, langPtr)
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	// Phase 1: Extract symbols and imports from every file.
	type fileInfo struct {
		pr      treesitter.ParseResult
		symbols []*treesitter.Symbol
		imports []treesitter.Import
		scope   *treesitter.Scope
	}
	fileInfos := make([]fileInfo, 0, len(parseResults))
	moduleSymbols := make(map[string][]*treesitter.Symbol)

	for _, pr := range parseResults {
		symbols, symErr := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if symErr != nil {
			continue
		}
		imports, impErr := ext.ResolveImports(pr.File, pr.Source, pr.Tree, input.SourceDir)
		if impErr != nil {
			continue
		}

		scope := treesitter.NewScope(nil)
		for _, imp := range imports {
			alias := imp.Alias
			if alias == "" {
				alias = imp.Module
			}
			scope.DefineImport(alias, imp.Module, imp.Symbols)
		}

		mod := moduleNameFrom(pr.File)
		moduleSymbols[mod] = symbols

		fileInfos = append(fileInfos, fileInfo{
			pr:      pr,
			symbols: symbols,
			imports: imports,
			scope:   scope,
		})
	}

	// Phase 2: Build the call graph.
	graph := treesitter.NewGraph()

	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			graph.AddSymbol(sym)
		}
	}

	// Phase 3: Extract call edges.
	for _, fi := range fileInfos {
		augScope := buildCrossFileScope(fi.imports, moduleSymbols, fi.scope)
		edges, edgeErr := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, augScope)
		if edgeErr != nil {
			continue
		}
		for _, e := range edges {
			e.To = resolveTarget(e.To, augScope)
			graph.AddEdge(e)
		}
	}

	// Phase 4: Inject TargetSymbols as virtual external nodes.
	targets := input.TargetSymbols
	if input.MaxTargets > 0 && len(targets) > input.MaxTargets {
		targets = targets[:input.MaxTargets]
	}

	targetSet := make(map[treesitter.SymbolID]struct{}, len(targets))
	for _, t := range targets {
		id := treesitter.SymbolID(t)
		targetSet[id] = struct{}{}
		if graph.GetSymbol(id) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         id,
				Name:       t,
				IsExternal: true,
				Language:   input.Language,
			})
		}
	}

	// Phase 5: Reverse BFS from each target to find all local callers.
	// We walk the reverse edges: for each target, find symbols that have a
	// forward edge leading (directly or transitively) to that target.
	reaching := make(map[treesitter.SymbolID]struct{})

	for targetID := range targetSet {
		visited := make(map[treesitter.SymbolID]bool)
		queue := []treesitter.SymbolID{targetID}
		visited[targetID] = true

		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]

			for _, rev := range graph.ReverseEdges(current) {
				if visited[rev.From] {
					continue
				}
				visited[rev.From] = true
				queue = append(queue, rev.From)

				// Only collect local (non-external) symbols.
				sym := graph.GetSymbol(rev.From)
				if sym == nil || sym.IsExternal {
					continue
				}
				if _, isTarget := targetSet[rev.From]; isTarget {
					continue
				}
				reaching[rev.From] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(reaching))
	for id := range reaching {
		result = append(result, string(id))
	}

	return HopResult{ReachingSymbols: result}, nil
}

// extractorForLanguage returns the LanguageExtractor, grammar language pointer,
// and file extension for the given language name.
func extractorForLanguage(lang string) (ext treesitter.LanguageExtractor, langPtr unsafe.Pointer, fileExt string, err error) { //nolint:nonamedreturns // gocritic requires named returns for clarity
	switch strings.ToLower(lang) {
	case "python":
		return pyextractor.New(), grammarpython.Language(), ".py", nil
	case "javascript", "js":
		return jsextractor.New(), grammarjs.Language(), ".js", nil
	default:
		return nil, nil, "", fmt.Errorf("unsupported language %q: only python and javascript are supported", lang)
	}
}

// moduleNameFrom derives a module/file name from an absolute path.
func moduleNameFrom(file string) string {
	base := filepath.Base(file)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// buildCrossFileScope constructs a scope that resolves imported symbols to their
// fully-qualified names across module boundaries.
func buildCrossFileScope(
	imports []treesitter.Import,
	moduleSymbols map[string][]*treesitter.Symbol,
	baseScope *treesitter.Scope,
) *treesitter.Scope {
	aug := treesitter.NewScope(baseScope)
	for _, imp := range imports {
		if len(imp.Symbols) == 0 {
			continue
		}
		for _, sym := range imp.Symbols {
			aug.Define(sym, imp.Module+"."+sym)
		}
	}
	_ = moduleSymbols // reserved for future cross-file resolution
	return aug
}

// resolveTarget resolves a call target SymbolID using the scope for
// cross-module symbol bindings.
func resolveTarget(to treesitter.SymbolID, scope *treesitter.Scope) treesitter.SymbolID {
	toStr := string(to)
	if strings.Contains(toStr, ".") {
		return to
	}
	if qualName, ok := scope.Lookup(toStr); ok {
		return treesitter.SymbolID(qualName)
	}
	return to
}
