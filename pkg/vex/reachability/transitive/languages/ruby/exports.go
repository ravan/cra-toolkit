// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby

import (
	"os"
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarruby "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/ruby"
	rubyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/ruby"
)

// ListExports walks the require-chain starting from the gem's entry file and
// returns the deduplicated set of dotted symbol keys for every public symbol
// reachable within the gem. External requires (e.g. "require 'json'") are
// silently skipped. If no entry file is found, all .rb files under lib/ are
// scanned as a fallback.
//
//nolint:gocognit,gocyclo // require-chain walk with fallback, parse loop, and symbol dispatch; splitting would obscure the algorithm
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	entryFile := findEntryFile(sourceDir, packageName)
	var files []string
	if entryFile != "" {
		files = walkRequireChain(entryFile, sourceDir)
	} else {
		// Fallback: all .rb files under lib/
		libDir := filepath.Join(sourceDir, "lib")
		_ = filepath.WalkDir(libDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(path, ".rb") {
				files = append(files, path)
			}
			return nil
		})
	}

	if len(files) == 0 {
		return nil, nil
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarruby.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		src, err := os.ReadFile(file) //nolint:gosec // file paths are resolved within sourceDir
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}

		ext := rubyextractor.New()
		symbols, err := ext.ExtractSymbols(file, src, tree)
		tree.Close()
		if err != nil {
			continue
		}

		modulePath := l.ModulePath(file, sourceDir, packageName)
		for _, sym := range symbols {
			if !l.IsExportedSymbol(sym) {
				continue
			}
			key := buildKey(modulePath, sym)
			if !seen[key] {
				seen[key] = true
			}
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	return keys, nil
}

// buildKey constructs the dotted symbol key for a symbol.
//
// Ruby extractor sets QualifiedName as:
//   - For classes/modules: "ClassName" or "Outer::Inner"
//   - For methods: "ClassName::methodName"
//
// The desired key format is:
//   - Class/module: modulePath + "." + QualifiedName  (e.g. "mygem.mygem.MyGem::Parser")
//   - Method: modulePath + "." + Package + "." + Name (e.g. "mygem.mygem.parser.MyGem::Parser.parse")
//
// This keeps the Ruby :: separator for class/module names as-is, while using
// . to separate the method name from its containing class — matching the
// test expectations.
func buildKey(modulePath string, sym *treesitter.Symbol) string {
	switch sym.Kind {
	case treesitter.SymbolClass, treesitter.SymbolModule:
		return modulePath + "." + sym.QualifiedName
	default:
		// Methods (including attr synthesized ones): Package holds the class name.
		if sym.Package != "" {
			return modulePath + "." + sym.Package + "." + sym.Name
		}
		return modulePath + "." + sym.QualifiedName
	}
}

// findEntryFile returns the conventional entry file for the gem at sourceDir.
// It tries the following candidates in order:
//  1. lib/<packageName>.rb  (e.g. lib/mygem.rb)
//  2. lib/<hyphen-to-slash>.rb  (e.g. lib/my/gem.rb for "my-gem")
//  3. lib/<hyphen-to-underscore>.rb  (e.g. lib/my_gem.rb for "my-gem")
func findEntryFile(sourceDir, packageName string) string {
	candidates := []string{
		filepath.Join(sourceDir, "lib", packageName+".rb"),
		filepath.Join(sourceDir, "lib", strings.ReplaceAll(packageName, "-", string(filepath.Separator))+".rb"),
		filepath.Join(sourceDir, "lib", strings.ReplaceAll(packageName, "-", "_")+".rb"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// walkRequireChain performs a depth-first walk of the require/require_relative
// graph starting from entryFile, returning absolute paths of every in-gem file
// visited. External requires that don't resolve to a file under sourceDir are
// silently skipped. Circular requires are handled via the visited set.
//
//nolint:gocognit // DFS with parser setup, visited tracking, and import resolution; splitting would obscure the traversal
func walkRequireChain(entryFile, sourceDir string) []string {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarruby.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil
	}

	ext := rubyextractor.New()
	visited := make(map[string]bool)
	var result []string

	var walk func(file string)
	walk = func(file string) {
		abs, err := filepath.Abs(file)
		if err != nil {
			return
		}
		if visited[abs] {
			return
		}
		visited[abs] = true
		result = append(result, abs)

		src, err := os.ReadFile(abs) //nolint:gosec // abs is resolved within sourceDir
		if err != nil {
			return
		}

		tree := parser.Parse(src, nil)
		if tree == nil {
			return
		}

		imports, err := ext.ResolveImports(abs, src, tree, "")
		tree.Close()
		if err != nil {
			return
		}

		for _, imp := range imports {
			resolved := resolveRequire(imp.Module, abs, sourceDir)
			if resolved != "" {
				walk(resolved)
			}
		}
	}

	walk(entryFile)
	return result
}

// resolveRequire attempts to resolve a require/require_relative module path to
// an absolute file path within the gem. It tries:
//  1. Relative to the current file's directory (covers require_relative)
//  2. Relative to lib/ (covers require with a bare gem-relative path)
//
// Returns an empty string if no matching file is found (external dependency).
func resolveRequire(module, currentFile, sourceDir string) string {
	dir := filepath.Dir(currentFile)
	candidates := []string{
		filepath.Join(dir, module+".rb"),
		filepath.Join(dir, module),
		filepath.Join(sourceDir, "lib", module+".rb"),
		filepath.Join(sourceDir, "lib", module),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	return ""
}
