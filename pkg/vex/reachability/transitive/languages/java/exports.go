// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package java

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	grammarjava "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/java"
	javaextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/java"
)

// skipDirs are directories excluded from export scanning.
var skipDirs = map[string]bool{
	"test": true, "tests": true, "src/test": true,
}

// ListExports enumerates the public API of a Java package by scanning
// source files. Uses src/main/java/ when present, falls back to root.
// Test directories (src/test/, test/, tests/) are excluded.
//
//nolint:gocognit,gocyclo // file walk, parse loop, and symbol filtering
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	scanRoot := sourceDir
	mainJava := filepath.Join(sourceDir, "src", "main", "java")
	if info, err := os.Stat(mainJava); err == nil && info.IsDir() {
		scanRoot = mainJava
	}

	var files []string
	_ = filepath.WalkDir(scanRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(sourceDir, path)
			if relErr == nil {
				for skip := range skipDirs {
					if rel == skip || strings.HasPrefix(rel, skip+string(filepath.Separator)) {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".java") {
			files = append(files, path)
		}
		return nil
	})
	if len(files) == 0 {
		return nil, nil
	}

	parser := tree_sitter.NewParser()
	defer parser.Close()
	lang := tree_sitter.NewLanguage(grammarjava.Language())
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

		ext := javaextractor.New()
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
