// Package java implements a tree-sitter-based reachability analyzer for Java.
package java

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	javagrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/java"
	javaextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/java"
)

// Analyzer performs Java reachability analysis using tree-sitter AST parsing.
type Analyzer struct{}

// New returns a new Java tree-sitter reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

// Language returns "java".
func (a *Analyzer) Language() string { return "java" }

// mavenImportPrefix maps Maven artifactId → Java import prefix.
// Used to expand short symbol names (e.g. "info") into qualified call targets
// when the finding's Symbols already include the object name (e.g. "logger.info").
// Only entries where a mapping is needed are listed; the default falls back to
// using the symbol as-is (since Java findings typically include the object qualifier).
var mavenImportPrefix = map[string]string{
	"log4j-core":              "org.apache.logging.log4j",
	"log4j-api":               "org.apache.logging.log4j",
	"spring-boot-starter-web": "org.springframework",
	"spring-web":              "org.springframework",
	"spring-context":          "org.springframework",
	"jackson-databind":        "com.fasterxml.jackson.databind",
	"guava":                   "com.google.common",
	"commons-lang3":           "org.apache.commons.lang3",
	"commons-collections4":    "org.apache.commons.collections4",
	"snakeyaml":               "org.yaml.snakeyaml",
	"fastjson":                "com.alibaba.fastjson",
	"xstream":                 "com.thoughtworks.xstream",
	"groovy":                  "groovy",
	"groovy-all":              "groovy",
}

// fileInfo holds per-file parse and extraction results.
type fileInfo struct {
	pr      treesitter.ParseResult
	symbols []*treesitter.Symbol
	imports []treesitter.Import
	scope   *treesitter.Scope
}

// Analyze parses all Java files in sourceDir, builds a call graph, and checks
// whether any of the vulnerable symbols from the finding are reachable from an entry point.
//
//nolint:gocognit,gocyclo,maintidx // pipeline has multiple orchestration phases; extracting further would reduce readability
func (a *Analyzer) Analyze(_ context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	// Collect all Java files via WalkDir
	var javaFiles []string
	if err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".java") {
			javaFiles = append(javaFiles, path)
		}
		return nil
	}); err != nil {
		return reachability.Result{}, fmt.Errorf("walk %s: %w", sourceDir, err)
	}

	if len(javaFiles) == 0 {
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   "no Java source files found in " + sourceDir,
		}, nil
	}

	// Parse all files
	parseResults, parseErrs := treesitter.ParseFiles(javaFiles, javagrammar.Language())
	parseErrCount := len(parseErrs)
	defer func() {
		for _, pr := range parseResults {
			pr.Tree.Close()
		}
	}()

	ext := javaextractor.New()

	// Phase 1: Extract all symbols and imports from ALL files first.
	// This is critical for Java CHA: the extractor builds the CHA table
	// (interface → implementors) during ExtractSymbols. All files must be
	// processed before ExtractCalls so that cross-file interface dispatch
	// is resolved correctly.
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

	// Snapshot the accumulated CHA state before Phase 3 resets it per-file.
	// After processing all files above, the extractor holds the union of all
	// interface→implementor mappings across the entire codebase. We capture
	// this now so it can be merged back in Phase 3 before each ExtractCalls.
	chaSnapshot := ext.SnapshotCHA()

	// Phase 2: Build the call graph
	graph := treesitter.NewGraph()

	// Add all known symbols to the graph
	for _, fi := range fileInfos {
		for _, sym := range fi.symbols {
			graph.AddSymbol(sym)
		}
	}

	// Phase 3: Extract calls and add edges.
	// The Java extractor resets its CHA/paramTypes state on each ExtractSymbols call,
	// so we must re-run ExtractSymbols to restore per-file symbols, then immediately
	// merge back the full cross-file CHA snapshot so that interface dispatch across
	// files is resolved correctly before ExtractCalls runs.
	for _, fi := range fileInfos {
		// Restore per-file symbols (resets extractor state for this file)
		if _, err := ext.ExtractSymbols(fi.pr.File, fi.pr.Source, fi.pr.Tree); err != nil {
			continue
		}
		// Merge back the full cross-file CHA so interface dispatch sees all implementors
		ext.RestoreCHA(chaSnapshot)

		edges, err := ext.ExtractCalls(fi.pr.File, fi.pr.Source, fi.pr.Tree, fi.scope)
		if err != nil {
			continue
		}

		for _, e := range edges {
			graph.AddEdge(e)
		}
	}

	// Phase 4: Find entry points
	allSymbols := graph.AllSymbols()
	entryPoints := ext.FindEntryPoints(allSymbols, sourceDir)

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
	// For Java, finding.Symbols typically contains qualified call targets like
	// "logger.info" (as produced by the extractor when processing logger.info(...)).
	// We use the symbols directly as target IDs.
	targets := buildTargetIDs(finding.AffectedName, finding.Symbols)

	// Add targets as virtual nodes in the graph so BFS can find them
	for _, targetID := range targets {
		if graph.GetSymbol(targetID) == nil {
			graph.AddSymbol(&treesitter.Symbol{
				ID:         targetID,
				Name:       string(targetID),
				IsExternal: true,
				Language:   "java",
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
// For Java, finding.Symbols may be:
//   - Simple method names like "info" → we prefix with the import prefix for the artifact,
//     e.g. "log4j-core" maps to "org.apache.logging.log4j", giving "org.apache.logging.log4j.info"
//   - Already-qualified call targets like "logger.info" → used as-is, since the extractor
//     emits edges with target "logger.info" when it sees logger.info(...) in the source.
//
// The "as-is" path handles CVE-2021-44228 correctly: the finding has Symbols=["logger.info"]
// and the extractor produces edges To="logger.info".
func buildTargetIDs(artifactName string, symbols []string) []treesitter.SymbolID {
	ids := make([]treesitter.SymbolID, 0, len(symbols))
	for _, sym := range symbols {
		if strings.Contains(sym, ".") {
			// Already qualified (e.g. "logger.info", "org.apache.logging.log4j.Logger.info")
			ids = append(ids, treesitter.SymbolID(sym))
		} else {
			// Simple name — try to qualify with maven import prefix
			if prefix, ok := mavenImportPrefix[artifactName]; ok {
				ids = append(ids, treesitter.SymbolID(prefix+"."+sym))
			} else {
				// Fall back: use as-is
				ids = append(ids, treesitter.SymbolID(sym))
			}
		}
	}
	return ids
}
