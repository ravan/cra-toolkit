// Package python implements a tree-sitter-based reachability analyzer for Python.
package python

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	grammarpython "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	pyextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// Analyzer performs Python reachability analysis using tree-sitter AST parsing.
type Analyzer struct{}

// New returns a new Python tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "python".
func (a *Analyzer) Language() string { return "python" }

// pypiImportName maps PyPI package names to their Python import names.
// Only non-obvious mappings are listed; the default is lowercase(name).
var pypiImportName = map[string]string{
	"PyYAML":            "yaml",
	"Pillow":            "PIL",
	"scikit-learn":      "sklearn",
	"beautifulsoup4":    "bs4",
	"python-dateutil":   "dateutil",
	"opencv-python":     "cv2",
	"mysqlclient":       "MySQLdb",
	"pycrypto":          "Crypto",
	"dnspython":         "dns",
	"python-magic":      "magic",
	"python-dotenv":     "dotenv",
	"psycopg2-binary":   "psycopg2",
	"google-auth":       "google.auth",
	"google-cloud":      "google.cloud",
	"protobuf":          "google.protobuf",
	"grpcio":            "grpc",
	"pydantic":          "pydantic",
	"typing-extensions": "typing_extensions",
}

// rowToLine converts a tree-sitter 0-based row to a 1-based line number.
// Tree-sitter uses uint for rows; source files never exceed max int lines.
func rowToLine(row uint) int {
	return int(row) + 1 //nolint:gosec // row is a line number, never overflows int
}

// importNameForPackage returns the Python import name for a given PyPI package name.
func importNameForPackage(pypiName string) string {
	if name, ok := pypiImportName[pypiName]; ok {
		return name
	}
	// Default: lowercase and replace hyphens with underscores
	return strings.ReplaceAll(strings.ToLower(pypiName), "-", "_")
}

// fileInfo holds per-file parse and extraction results.
type fileInfo struct {
	pr      treesitter.ParseResult
	symbols []*treesitter.Symbol
	imports []treesitter.Import
	scope   *treesitter.Scope
}

// Analyze parses all Python files in sourceDir, builds a call graph, and checks
// whether any of the vulnerable symbols from the finding are reachable from an
// entry point.
//
//nolint:gocognit,gocyclo // pipeline has multiple orchestration phases; extracting further would reduce readability
func (a *Analyzer) Analyze(_ context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Collect all Python files via WalkDir (filepath.Glob("**/*.py") doesn't work in Go)
	var files []string
	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".py") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return reachability.Result{}, fmt.Errorf("walk %s: %w", sourceDir, err)
	}

	if len(files) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "no Python source files found in " + sourceDir,
		}, nil
	}

	// Determine the import name of the vulnerable package
	importName := importNameForPackage(finding.AffectedName)

	// Parse all files
	parseResults, parseErrs := treesitter.ParseFiles(files, grammarpython.Language())
	// Non-fatal: partial analysis is better than no analysis.
	// Parse errors are tracked and included in the evidence string so callers
	// can see degraded coverage (e.g. syntax errors in vendored files).
	parseErrCount := len(parseErrs)
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	ext := pyextractor.New()

	// Phase 1: Extract all symbols and imports from all files.
	// Build a map of module name → symbols for cross-file resolution.
	fileInfos := make([]fileInfo, 0, len(parseResults))
	// module name → []*Symbol for cross-file import resolution
	moduleSymbols := make(map[string][]*treesitter.Symbol)

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

	// Phase 3: Extract calls and add edges, with cross-file resolution
	for _, fi := range fileInfos {
		// Build an augmented scope that resolves cross-file imports.
		// For "from handler import process_config", we resolve process_config
		// to handler.process_config.
		augScope := buildAugmentedScope(fi.imports, moduleSymbols, fi.scope)

		edges, err := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, augScope)
		if err != nil {
			continue
		}

		for _, e := range edges {
			// Resolve cross-file symbol references in the To field
			resolved := resolveEdgeTo(e.To, augScope, moduleSymbols)
			e.To = resolved
			graph.AddEdge(e)
		}

		// Also add top-level module edges for cross-file function calls.
		// When main.py does "from handler import process_config" and calls
		// process_config() at module level, we need an edge from main → handler.process_config.
		addCrossFileEdges(&fi, augScope, moduleSymbols, graph)
	}

	// Phase 4: Find entry points
	allSymbols := graph.AllSymbols()
	entryPoints := ext.FindEntryPoints(allSymbols, sourceDir)

	// Also treat __main__ module-level code as an entry point by adding a virtual
	// entry node for each file that has top-level calls.
	mainEntries := findMainModuleEntries(graph)
	entryPoints = append(entryPoints, mainEntries...)

	if len(entryPoints) == 0 {
		// Fall back: treat all top-level module symbols as entry points
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
	// For PyYAML with symbols=["load"], target is "yaml.load"
	targets := buildTargetIDs(importName, finding.Symbols)

	// Also add the targets as virtual nodes in the graph so BFS can find them
	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "python",
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

// moduleNameFromFile derives a Python module name from an absolute file path.
// "/project/src/handler.py" → "handler"
func moduleNameFromFile(file string) string {
	base := filepath.Base(file)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// buildTargetIDs creates SymbolIDs for the vulnerable symbols.
// For importName="yaml" and symbols=["load"], returns ["yaml.load"].
func buildTargetIDs(importName string, symbols []string) []treesitter.SymbolID {
	ids := make([]treesitter.SymbolID, 0, len(symbols))
	for _, sym := range symbols {
		ids = append(ids, treesitter.SymbolID(importName+"."+sym))
	}
	return ids
}

// buildAugmentedScope creates a scope that resolves cross-file imports.
// For "from handler import process_config", it registers "process_config" →
// "handler.process_config" in the scope.
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
		// "from handler import process_config"
		// imp.Module = "handler", imp.Symbols = ["process_config"]
		targetMod := imp.Module
		for _, sym := range imp.Symbols {
			qualifiedName := targetMod + "." + sym
			augScope.Define(sym, qualifiedName)
		}
	}
	return augScope
}

// resolveEdgeTo resolves a call's target, handling cross-file symbol references.
// If the target is "process_config" and the scope knows it resolves to
// "handler.process_config", use that.
func resolveEdgeTo(
	to treesitter.SymbolID,
	scope *treesitter.Scope,
	moduleSymbols map[string][]*treesitter.Symbol,
) treesitter.SymbolID {
	toStr := string(to)

	// If it already contains a dot and starts with a module we know, keep it
	// (e.g., "yaml.load" → "yaml.load")
	if strings.Contains(toStr, ".") {
		// Check if it's a module-qualified call we already know
		return to
	}

	// Try scope lookup for simple names
	if qualName, ok := scope.Lookup(toStr); ok {
		return treesitter.SymbolID(qualName)
	}

	return to
}

// addCrossFileEdges adds edges from module-level callers to cross-file functions.
// This handles the case where main.py calls process_config() at top level
// and process_config was imported from handler.py.
func addCrossFileEdges(
	fi *fileInfo,
	augScope *treesitter.Scope,
	_ map[string][]*treesitter.Symbol,
	graph *treesitter.Graph,
) {
	// Walk the tree to find top-level calls and calls in __main__ blocks
	addTopLevelCallEdges(fi.pr, augScope, graph)
}

// addTopLevelCallEdges finds calls at the module level (outside any function)
// and adds edges from a virtual module entry node to the callees.
func addTopLevelCallEdges(
	pr treesitter.ParseResult,
	scope *treesitter.Scope,
	graph *treesitter.Graph,
) {
	mod := moduleNameFromFile(pr.File)
	root := pr.Tree.RootNode()
	moduleID := treesitter.SymbolID(mod)

	// Ensure the module node exists in the graph
	if graph.GetSymbol(moduleID) == nil {
		graph.AddSymbol(&treesitter.Symbol{
			ID:            moduleID,
			Name:          mod,
			QualifiedName: mod,
			Language:      "python",
			File:          pr.File,
			Kind:          treesitter.SymbolModule,
			IsEntryPoint:  false,
		})
	}

	collectTopLevelCalls(root, pr.Source, pr.File, mod, scope, graph, moduleID)
}

// collectTopLevelCalls walks the AST at the module level to find direct calls.
//
//nolint:gocognit,gocyclo // AST walker for top-level calls and __main__ blocks requires branching on node kinds
func collectTopLevelCalls(
	node *tree_sitter.Node,
	src []byte,
	file, mod string,
	scope *treesitter.Scope,
	graph *treesitter.Graph,
	fromID treesitter.SymbolID,
) {
	if node == nil {
		return
	}

	switch node.Kind() {
	case "function_definition", "class_definition", "decorated_definition":
		// Don't recurse into function bodies — those are handled by collectCalls
		return

	case "call":
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			callee := resolveCalleeText(funcNode, src, scope)
			if callee != "" {
				graph.AddEdge(treesitter.Edge{
					From:       fromID,
					To:         treesitter.SymbolID(callee),
					Kind:       treesitter.EdgeDirect,
					Confidence: 1.0,
					File:       file,
					Line:       rowToLine(node.StartPosition().Row),
				})
			}
		}
		// Also recurse into arguments
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil {
			collectTopLevelCalls(argsNode, src, file, mod, scope, graph, fromID)
		}
		return

	case "if_statement":
		// Handle `if __name__ == "__main__":` blocks specially
		// These are entry points - treat calls inside them as entry point edges
		condNode := node.ChildByFieldName("condition")
		isMainBlock := false
		if condNode != nil {
			condText := condNode.Utf8Text(src)
			if strings.Contains(condText, "__name__") && strings.Contains(condText, "__main__") {
				isMainBlock = true
			}
		}
		if isMainBlock {
			// Create a virtual __main__ entry node
			mainID := treesitter.SymbolID(mod + ".__main__")
			if graph.GetSymbol(mainID) == nil {
				graph.AddSymbol(&treesitter.Symbol{
					ID:            mainID,
					Name:          "__main__",
					QualifiedName: mod + ".__main__",
					Language:      "python",
					File:          file,
					Kind:          treesitter.SymbolFunction,
					IsEntryPoint:  true,
				})
			}
			// Walk the body of the if block
			for i := uint(0); i < node.ChildCount(); i++ {
				child := node.Child(i)
				if child != nil && child.Kind() == "block" {
					collectTopLevelCalls(child, src, file, mod, scope, graph, mainID)
				}
			}
			return
		}
	}

	// Recurse into children
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectTopLevelCalls(child, src, file, mod, scope, graph, fromID)
	}
}

// resolveCalleeText extracts the callee name from a function node, using the scope
// to resolve cross-file imports.
//
//nolint:gocognit,gocyclo // callee resolution must handle attribute chains and identifiers
func resolveCalleeText(node *tree_sitter.Node, src []byte, scope *treesitter.Scope) string {
	if node == nil {
		return ""
	}

	switch node.Kind() {
	case "attribute":
		objNode := node.ChildByFieldName("object")
		attrNode := node.ChildByFieldName("attribute")
		if objNode != nil && attrNode != nil {
			obj := resolveCalleeText(objNode, src, scope)
			attr := attrNode.Utf8Text(src)
			if obj != "" {
				return obj + "." + attr
			}
			return attr
		}

	case "identifier":
		name := node.Utf8Text(src)
		// Check if this name has a scope binding (cross-file import)
		if qualified, ok := scope.Lookup(name); ok {
			return qualified
		}
		return name

	case "call":
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			return resolveCalleeText(funcNode, src, scope)
		}
	}

	return ""
}

// findMainModuleEntries returns SymbolIDs for virtual __main__ entry nodes.
func findMainModuleEntries(graph *treesitter.Graph) []treesitter.SymbolID {
	var eps []treesitter.SymbolID
	for _, sym := range graph.AllSymbols() {
		if sym.Name == "__main__" && sym.IsEntryPoint {
			eps = append(eps, sym.ID)
		}
	}
	return eps
}
