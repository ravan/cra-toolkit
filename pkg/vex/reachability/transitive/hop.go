// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// HopInput describes a single per-hop reachability query.
type HopInput struct {
	// Language is the LanguageSupport implementation for the source language.
	Language LanguageSupport
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
	if input.Language == nil {
		return HopResult{}, fmt.Errorf("RunHop: input.Language is nil")
	}
	ext := input.Language.Extractor()
	langPtr := input.Language.Grammar()
	fileExts := input.Language.FileExtensions()

	// Collect all source files matching any of the language's extensions.
	var files []string
	if walkErr := filepath.WalkDir(input.SourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		for _, ext := range fileExts {
			if strings.HasSuffix(path, ext) {
				files = append(files, path)
				return nil
			}
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

	stateful, hasCrossFileState := ext.(CrossFileStateExtractor)
	var snapshots []any

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
		if hasCrossFileState {
			snapshots = append(snapshots, stateful.SnapshotState())
		}
	}

	if hasCrossFileState {
		for _, s := range snapshots {
			stateful.RestoreState(s)
		}
	}

	// Phase 2: Build the call graph.
	graph := treesitter.NewGraph()

	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			graph.AddSymbol(sym)
		}
	}

	// Phase 2a: Add synthetic module-level symbols so that module-level
	// call/reference edges (e.g. `const x = bodyParser.urlencoded()` at the
	// top of a file) have a recognized local "caller" identity. Without this,
	// reverse BFS from a target would skip module-level callers because their
	// SymbolID (the bare module name) has no corresponding Symbol in the graph
	// and the walker filters out non-symbol nodes.
	//
	// This is load-bearing for the JavaScript cross-package case: the fixture
	// application has `bodyParser.urlencoded({...})` at module scope, which
	// emits an edge `app -> body-parser.urlencoded`; without a synthetic
	// `app` symbol the walker cannot surface that edge as a reaching caller.
	for _, fi := range fileInfos {
		mod := moduleNameFrom(fi.pr.File)
		if mod == "" {
			continue
		}
		modID := treesitter.SymbolID(mod)
		if graph.GetSymbol(modID) != nil {
			continue
		}
		graph.AddSymbol(&treesitter.Symbol{
			ID:            modID,
			Name:          mod,
			QualifiedName: mod,
			Language:      input.Language.Name(),
			File:          fi.pr.File,
			Package:       mod,
			Kind:          treesitter.SymbolFunction,
		})
	}

	// Phase 2b: Add synthetic class → class.__init__ edges so that
	// constructor call sites (e.g. HTTPAdapter()) can reach __init__ body.
	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			if sym.Kind != treesitter.SymbolClass {
				continue
			}
			initID := treesitter.SymbolID(string(sym.ID) + ".__init__")
			if graph.GetSymbol(initID) != nil {
				graph.AddEdge(treesitter.Edge{From: sym.ID, To: initID})
			}
		}
	}

	// Phase 3: Extract call edges.
	for _, fi := range fileInfos {
		augScope := buildCrossFileScope(fi.imports, moduleSymbols, fi.scope, input.Language)
		mod := moduleNameFrom(fi.pr.File)
		edges, edgeErr := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, augScope)
		if edgeErr != nil {
			continue
		}
		for _, e := range edges {
			e.To = resolveTarget(e.To, augScope, mod, input.Language)
			e.To = input.Language.ResolveSelfCall(e.To, e.From)
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
				Language:   input.Language.Name(),
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
	lang LanguageSupport,
) *treesitter.Scope {
	normalized := lang.NormalizeImports(imports)
	aug := treesitter.NewScope(baseScope)
	for _, imp := range normalized {
		// Register alias → module mapping even when no named symbols are
		// listed. This covers patterns like `const mod = require('qs')`
		// where the entire module is bound to an alias (Alias="mod",
		// Symbols=[]) so that dotted calls such as `mod.parse` can later
		// be resolved to `qs.parse`.
		if imp.Alias != "" && imp.Module != "" {
			aug.DefineImport(imp.Alias, imp.Module, imp.Symbols)
		}
		for _, sym := range imp.Symbols {
			aug.Define(sym, imp.Module+"."+sym)
		}
	}
	_ = moduleSymbols // reserved for future cross-file resolution
	return aug
}

// resolveTarget resolves a call target SymbolID using the scope for
// cross-module symbol bindings. For bare names not found in scope, it falls
// back to qualifying with localMod (the calling file's module name), which
// covers same-file function calls (e.g., call to "request" in api.py
// resolves to "api.request").
func resolveTarget(to treesitter.SymbolID, scope *treesitter.Scope, localMod string, lang LanguageSupport) treesitter.SymbolID {
	toStr := string(to)
	if dotIdx := strings.Index(toStr, "."); dotIdx >= 0 {
		prefix := toStr[:dotIdx]
		suffix := toStr[dotIdx+1:]
		if resolved, ok := lang.ResolveDottedTarget(prefix, suffix, scope); ok {
			return resolved
		}
		return to
	}
	if qualName, ok := scope.Lookup(toStr); ok {
		return treesitter.SymbolID(qualName)
	}
	if localMod != "" {
		return treesitter.SymbolID(localMod + "." + toStr)
	}
	return to
}
