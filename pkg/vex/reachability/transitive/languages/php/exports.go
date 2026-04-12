// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package php

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	grammarphp "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/php"
	phpextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/php"
)

// composerJSON is the subset of composer.json we consume.
type composerJSON struct {
	Autoload struct {
		PSR4 map[string]string `json:"psr-4"`
	} `json:"autoload"`
}

// ListExports enumerates the public API of a PHP package by following
// the PSR-4 autoload mapping from composer.json. Falls back to scanning
// src/, lib/, or the root directory when composer.json is absent.
//
//nolint:gocognit,gocyclo // PSR-4 walk with fallback, parse loop, and symbol filtering
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	var dirs []string
	cj := readComposerJSON(sourceDir)
	if cj != nil && len(cj.Autoload.PSR4) > 0 {
		for _, dir := range cj.Autoload.PSR4 {
			absDir := filepath.Join(sourceDir, dir)
			if info, err := os.Stat(absDir); err == nil && info.IsDir() {
				dirs = append(dirs, absDir)
			}
		}
	}
	if len(dirs) == 0 {
		dirs = fallbackDirs(sourceDir)
	}
	if len(dirs) == 0 {
		return nil, nil
	}

	var files []string
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(path, ".php") {
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
	lang := tree_sitter.NewLanguage(grammarphp.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		src, err := os.ReadFile(file) //nolint:gosec // file paths resolved within sourceDir
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}

		ext := phpextractor.New()
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
			key := l.SymbolKey(modulePath, sym.Name)
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

// readComposerJSON reads and parses composer.json from sourceDir.
// Returns nil if the file does not exist or is invalid.
func readComposerJSON(sourceDir string) *composerJSON {
	data, err := os.ReadFile(filepath.Join(sourceDir, "composer.json")) //nolint:gosec // composer.json path is constructed from a caller-supplied sourceDir
	if err != nil {
		return nil
	}
	var cj composerJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil
	}
	return &cj
}

// fallbackDirs returns directories to scan when composer.json has no
// PSR-4 mapping. Tries src/, then lib/, then the root.
func fallbackDirs(sourceDir string) []string {
	candidates := []string{
		filepath.Join(sourceDir, "src"),
		filepath.Join(sourceDir, "lib"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return []string{c}
		}
	}
	return []string{sourceDir}
}
