// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csharp

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	csharpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/csharp"
	grammarcsharp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/csharp"
)

// skipDirs are directories excluded from export scanning.
var skipDirs = map[string]bool{
	"obj": true, "bin": true, "test": true, "tests": true,
}

// skipDirPatterns match directory names containing these substrings.
var skipDirPatterns = []string{"Test", "Tests", "Spec"}

// ListExports enumerates the public API of a C# package by scanning
// source files. Excludes obj/, bin/, and test directories.
//
//nolint:gocognit,gocyclo // file walk, parse loop, and symbol filtering
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	var files []string
	_ = filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if skipDirs[name] {
				return filepath.SkipDir
			}
			for _, pat := range skipDirPatterns {
				if strings.Contains(name, pat) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".cs") {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil, nil
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarcsharp.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		src, err := os.ReadFile(file) //nolint:gosec // paths resolved within sourceDir
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}

		ext := csharpextractor.New()
		symbols, err := ext.ExtractSymbols(file, src, tree)
		tree.Close()
		if err != nil {
			continue
		}

		for _, sym := range symbols {
			if !l.IsExportedSymbol(sym) {
				continue
			}
			key := sym.QualifiedName
			if key == "" {
				continue
			}
			seen[key] = true
		}
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}
