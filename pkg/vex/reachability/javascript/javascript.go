// Package javascript implements a tree-sitter-based reachability analyzer for JavaScript and TypeScript.
package javascript

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	jsgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	tsgrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/typescript"
	jsextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/javascript"
)

// Analyzer performs JavaScript/TypeScript reachability analysis using tree-sitter AST parsing.
type Analyzer struct{}

// New returns a new JavaScript/TypeScript tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "javascript".
func (a *Analyzer) Language() string { return "javascript" }

// npmImportName maps npm package names to their JavaScript import names.
// Only non-obvious mappings are listed; the default is the package name itself.
var npmImportName = map[string]string{
	"lodash":        "lodash",
	"lodash-es":     "lodash-es",
	"express":       "express",
	"react":         "react",
	"vue":           "vue",
	"next":          "next",
	"@types/lodash": "lodash",
	"@types/node":   "node",
	"axios":         "axios",
	"moment":        "moment",
	"dayjs":         "dayjs",
	"underscore":    "underscore",
	"ramda":         "ramda",
	"rxjs":          "rxjs",
	"zod":           "zod",
}

// jsExtensions contains file extensions for JavaScript files that use the JS grammar.
var jsExtensions = map[string]bool{
	".js":  true,
	".jsx": true,
	".mjs": true,
	".cjs": true,
}

// tsExtensions contains file extensions for TypeScript files that use the TS grammar.
var tsExtensions = map[string]bool{
	".ts":  true,
	".tsx": true,
}

// isJSOrTS returns true if the file path has a JS or TS extension.
func isJSOrTS(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return jsExtensions[ext] || tsExtensions[ext]
}

// isTypeScript returns true if the file uses the TypeScript grammar.
func isTypeScript(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return tsExtensions[ext]
}

// importNameForPackage returns the JavaScript import name for a given npm package name.
func importNameForPackage(npmName string) string {
	if name, ok := npmImportName[npmName]; ok {
		return name
	}
	// Default: package name as-is (npm names are already the import names for JS)
	return npmName
}

// fileInfo holds per-file parse and extraction results.
type fileInfo struct {
	pr      treesitter.ParseResult
	symbols []*treesitter.Symbol
	imports []treesitter.Import
	scope   *treesitter.Scope
}

// Analyze parses all JavaScript/TypeScript files in sourceDir, builds a call graph, and checks
// whether any of the vulnerable symbols from the finding are reachable from an entry point.
//
//nolint:gocognit,gocyclo,maintidx // pipeline has multiple orchestration phases; extracting further would reduce readability
func (a *Analyzer) Analyze(_ context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Collect all JS/TS files via WalkDir (filepath.Glob("**/*.js") doesn't work in Go)
	var jsFiles, tsFiles []string
	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isTypeScript(path) {
			tsFiles = append(tsFiles, path)
		} else if isJSOrTS(path) {
			jsFiles = append(jsFiles, path)
		}
		return nil
	}); err != nil {
		return reachability.Result{}, fmt.Errorf("walk %s: %w", sourceDir, err)
	}

	if len(jsFiles)+len(tsFiles) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "no JavaScript/TypeScript source files found in " + sourceDir,
		}, nil
	}

	// Determine the import name of the vulnerable package
	importName := importNameForPackage(finding.AffectedName)

	// Parse all files using the correct grammar per file type
	parseErrCount := 0
	var allParseResults []treesitter.ParseResult

	if len(jsFiles) > 0 {
		jsParsed, jsErrs := treesitter.ParseFiles(jsFiles, jsgrammar.Language())
		parseErrCount += len(jsErrs)
		allParseResults = append(allParseResults, jsParsed...)
	}
	if len(tsFiles) > 0 {
		tsParsed, tsErrs := treesitter.ParseFiles(tsFiles, tsgrammar.Language())
		parseErrCount += len(tsErrs)
		allParseResults = append(allParseResults, tsParsed...)
	}

	defer func() {
		for _, pr := range allParseResults {
			pr.Tree.Close()
		}
	}()

	ext := jsextractor.New()

	// Phase 1: Extract all symbols and imports from all files.
	// Build a map of module name → symbols for cross-file resolution.
	fileInfos := make([]fileInfo, 0, len(allParseResults))
	moduleSymbols := make(map[string][]*treesitter.Symbol)

	for _, pr := range allParseResults {
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

		mod := moduleNameFromFile(pr.File)
		moduleSymbols[mod] = symbols

		fileInfos = append(fileInfos, fileInfo{
			pr:      pr,
			symbols: symbols,
			imports: imports,
			scope:   scope,
		})
	}

	// Phase 2: Build the call graph
	graph := treesitter.NewGraph()

	// Add all known symbols to the graph
	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			graph.AddSymbol(sym)
		}
	}

	// Phase 3: Extract calls and add edges, with cross-file resolution.
	// Pass fi.scope (which holds DefineImport entries for CJS require/ESM import aliases)
	// to ExtractCalls so that resolveAliasInCallee can rewrite "_.template" → "lodash.template".
	// augScope is only needed for Python-style "from module import symbol" cross-file resolution
	// which JS doesn't use in the same way.
	for _, fi := range fileInfos {
		augScope := buildAugmentedScope(fi.imports, moduleSymbols, fi.scope)

		edges, err := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, fi.scope)
		if err != nil {
			continue
		}

		for _, e := range edges {
			resolved := resolveEdgeTo(e.To, augScope)
			e.To = resolved
			graph.AddEdge(e)
		}
	}

	// Phase 4: Find entry points
	allSymbols := graph.AllSymbols()
	entryPoints := ext.FindEntryPoints(allSymbols, sourceDir)

	// Also add module-level virtual entry nodes for files with top-level calls.
	// In JS apps, top-level code runs at module load time (e.g., app.post registrations).
	// We create virtual module entry nodes for each file and add them as entry points.
	for _, fi := range fileInfos {
		modName := moduleNameFromFile(fi.pr.File)
		modID := treesitter.SymbolID(modName)
		if graph.GetSymbol(modID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:            modID,
				Name:          modName,
				QualifiedName: modName,
				Language:      "javascript",
				File:          fi.pr.File,
				Kind:          treesitter.SymbolModule,
				IsEntryPoint:  true,
			})
		}
		entryPoints = append(entryPoints, modID)
	}

	if len(entryPoints) == 0 {
		// Fall back: treat all functions/methods as entry points
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

	// Phase 5: Build target symbol IDs from the finding
	// For lodash with symbols=["template"], target is "lodash.template"
	targets := buildTargetIDs(importName, finding.Symbols)

	// Add targets as virtual nodes in the graph so BFS can find them
	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "javascript",
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
			Evidence:   fmt.Sprintf("tree-sitter analysis found no call path to %s.{%s}%s", importName, strings.Join(finding.Symbols, ","), parseErrSuffix),
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

// moduleNameFromFile derives a module name from a JS/TS file path.
// "handler.js" → "handler", "routes/api.ts" → "api"
func moduleNameFromFile(file string) string {
	base := filepath.Base(file)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	name = strings.ReplaceAll(name, "+", "_")
	return name
}

// buildTargetIDs creates SymbolIDs for the vulnerable symbols.
// For importName="lodash" and symbols=["template"], returns ["lodash.template"].
func buildTargetIDs(importName string, symbols []string) []treesitter.SymbolID {
	ids := make([]treesitter.SymbolID, 0, len(symbols))
	for _, sym := range symbols {
		ids = append(ids, treesitter.SymbolID(importName+"."+sym))
	}
	return ids
}

// buildAugmentedScope creates a scope that resolves cross-file imports.
func buildAugmentedScope(
	imports []treesitter.Import,
	moduleSymbols map[string][]*treesitter.Symbol,
	baseScope *treesitter.Scope,
) *treesitter.Scope {
	augScope := treesitter.NewScope(baseScope)
	for _, imp := range imports {
		if len(imp.Symbols) == 0 {
			continue
		}
		targetMod := imp.Module
		for _, sym := range imp.Symbols {
			qualifiedName := targetMod + "." + sym
			augScope.Define(sym, qualifiedName)
		}
	}
	return augScope
}

// resolveEdgeTo resolves a call's target symbol ID using scope.
func resolveEdgeTo(to treesitter.SymbolID, scope *treesitter.Scope) treesitter.SymbolID {
	toStr := string(to)
	if strings.Contains(toStr, ".") {
		return to
	}
	if qualName, ok := scope.Lookup(toStr); ok {
		return treesitter.SymbolID(qualName)
	}
	return to
}
