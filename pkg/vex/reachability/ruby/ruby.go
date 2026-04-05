// Package ruby implements a tree-sitter-based reachability analyzer for Ruby.
package ruby

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	rubygrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/ruby"
	rubyextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/ruby"
)

// Compile-time interface conformance check.
// If the Analyzer methods diverge from the reachability.Analyzer interface,
// this line will produce a compile error pointing directly at the mismatch.
var _ reachability.Analyzer = (*Analyzer)(nil)

// Analyzer performs Ruby reachability analysis using tree-sitter AST parsing.
type Analyzer struct{}

// New returns a new Ruby tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "ruby".
func (a *Analyzer) Language() string { return "ruby" }

// gemModuleMap maps gem names to their Ruby module/class names for symbol resolution.
// This handles gems whose module name differs from the gem name.
var gemModuleMap = map[string]string{
	"nokogiri":      "Nokogiri",
	"rails":         "Rails",
	"activesupport": "ActiveSupport",
	"activerecord":  "ActiveRecord",
	"actionpack":    "ActionPack",
	"faraday":       "Faraday",
	"httparty":      "HTTParty",
	"rest-client":   "RestClient",
	"sidekiq":       "Sidekiq",
	"devise":        "Devise",
	"omniauth":      "OmniAuth",
}

// fileInfo holds per-file parse and extraction results.
type fileInfo struct {
	pr      treesitter.ParseResult
	symbols []*treesitter.Symbol
	imports []treesitter.Import
	scope   *treesitter.Scope
}

// Analyze parses all Ruby files in sourceDir, builds a call graph, and checks
// whether any of the vulnerable symbols from the finding are reachable from an entry point.
//
//nolint:gocognit,gocyclo,maintidx // pipeline has multiple orchestration phases
func (a *Analyzer) Analyze(_ context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Collect all Ruby files via WalkDir
	var rubyFiles []string
	var routesFile string

	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".rb") {
			rubyFiles = append(rubyFiles, path)
			// Track routes.rb for Rails route parsing
			if filepath.Base(path) == "routes.rb" {
				routesFile = path
			}
		}
		return nil
	}); err != nil {
		return reachability.Result{}, fmt.Errorf("walk %s: %w", sourceDir, err)
	}

	if len(rubyFiles) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "no Ruby source files found in " + sourceDir,
		}, nil
	}

	// Parse all Ruby files concurrently
	parseResults, parseErrs := treesitter.ParseFiles(rubyFiles, rubygrammar.Language())
	parseErrCount := len(parseErrs)
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	ext := rubyextractor.New()

	// Parse routes.rb first to register Rails routes before finding entry points
	if routesFile != "" {
		for _, pr := range parseResults {
			if pr.File == routesFile {
				if err := ext.RegisterRoutes(pr.Source, pr.Tree); err != nil {
					// Non-fatal: fall back to heuristic entry point detection
					_ = err
				}
				break
			}
		}
	}

	// Phase 1: Extract all symbols and imports from ALL files.
	// Collect entry points immediately after ExtractSymbols while extractor state is fresh.
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
	// When no specific symbols are provided, collect all calls to the gem's module from the graph.
	symbols := finding.Symbols
	if len(symbols) == 0 {
		if moduleName, ok := gemModuleMap[finding.AffectedName]; ok {
			symbols = collectGemCallsFromGraph(graph, moduleName)
		}
	}
	targets := buildTargetIDs(finding.AffectedName, symbols)

	// Add targets as virtual nodes in the graph so BFS can find them
	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "ruby",
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

	// Check for method_missing definitions — log as unresolved evidence note.
	methodMissingSuffix := ""
	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			if sym.Name == "method_missing" {
				methodMissingSuffix = "; note: method_missing detected in source; dynamic dispatch may be unresolved"
				break
			}
		}
		if methodMissingSuffix != "" {
			break
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
			Evidence:   fmt.Sprintf("tree-sitter analysis found no call path to {%s}%s%s", strings.Join(finding.Symbols, ","), parseErrSuffix, methodMissingSuffix),
		}, nil
	}

	evidence := fmt.Sprintf("tree-sitter call graph: %s is reachable via %d path(s): %s%s%s",
		strings.Join(reachedSymbols, ", "),
		len(allPaths),
		allPaths[0].String(),
		parseErrSuffix,
		methodMissingSuffix,
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
// For Ruby, finding.Symbols may be:
//   - "Nokogiri::HTML" → used as-is for scope resolution call matching
//   - "Nokogiri.HTML" → also convert to "Nokogiri::HTML" (Ruby uses ::)
//
// The extractor emits edges with targets like "Nokogiri::HTML" (scope resolution).
func buildTargetIDs(artifactName string, symbols []string) []treesitter.SymbolID {
	ids := make([]treesitter.SymbolID, 0, len(symbols)*3)

	for _, sym := range symbols {
		// Add as-is
		ids = append(ids, treesitter.SymbolID(sym))

		// Convert dot notation to double-colon: "Nokogiri.HTML" → "Nokogiri::HTML"
		if strings.Contains(sym, ".") && !strings.Contains(sym, "::") {
			ids = append(ids, treesitter.SymbolID(strings.ReplaceAll(sym, ".", "::")))
		}

		// Convert double-colon to dot notation: "Nokogiri::HTML" → "Nokogiri.HTML"
		if strings.Contains(sym, "::") {
			ids = append(ids, treesitter.SymbolID(strings.ReplaceAll(sym, "::", ".")))
		}
	}

	// Also add module-qualified forms derived from the gem name
	if moduleName, ok := gemModuleMap[artifactName]; ok {
		for _, sym := range symbols {
			// If the symbol doesn't start with the module name, add a module-prefixed form
			if !strings.HasPrefix(sym, moduleName) {
				ids = append(ids, treesitter.SymbolID(moduleName+"::"+sym))
			}
		}
	}

	return dedup(ids)
}

// collectGemCallsFromGraph scans the call graph for edges targeting the given
// module name prefix (e.g. "Nokogiri") and returns the distinct qualified symbols found
// (e.g. ["Nokogiri::HTML", "Nokogiri::XML"]). This is used when the finding doesn't specify
// individual symbols so we can detect any usage of the gem's module.
func collectGemCallsFromGraph(graph *treesitter.Graph, moduleName string) []string {
	prefixColon := moduleName + "::"
	prefixDot := moduleName + "."
	seen := make(map[string]struct{})
	for _, sym := range graph.AllSymbols() {
		for _, edge := range graph.ForwardEdges(sym.ID) {
			toStr := string(edge.To)
			if strings.HasPrefix(toStr, prefixColon) || strings.HasPrefix(toStr, prefixDot) {
				seen[toStr] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for m := range seen {
		result = append(result, m)
	}
	return result
}

// dedup removes duplicate SymbolIDs while preserving order.
func dedup(ids []treesitter.SymbolID) []treesitter.SymbolID {
	seen := make(map[treesitter.SymbolID]bool, len(ids))
	result := make([]treesitter.SymbolID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}
	return result
}
