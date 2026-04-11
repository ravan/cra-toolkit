// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// listExportedSymbols extracts the public API of a package at sourceDir as
// fully-qualified symbol IDs. The exact key scheme is language-specific and
// decided by lang.SymbolKey; for Python this produces dotted keys like
// "urllib3.poolmanager.PoolManager" and for JavaScript this produces flat
// keys like "body-parser.urlencoded".
//
//nolint:gocognit // parse-and-collect pattern; splitting further would obscure intent
func listExportedSymbols(lang LanguageSupport, sourceDir, packageName string) ([]string, error) {
	if lister, ok := lang.(ExportLister); ok {
		return lister.ListExports(sourceDir, packageName)
	}
	files, err := collectFilesByExt(sourceDir, lang.FileExtensions())
	if err != nil {
		return nil, err
	}
	parsed, _ := treesitter.ParseFiles(files, lang.Grammar())
	defer func() {
		for _, pr := range parsed {
			pr.Tree.Close()
		}
	}()
	ext := lang.Extractor()
	seen := make(map[string]struct{})
	for _, pr := range parsed {
		mod := lang.ModulePath(pr.File, sourceDir, packageName)
		// Skip files outside the package itself (tests, docs, examples).
		// A valid package module starts with "packageName." or equals
		// "packageName" — this filter is language-agnostic because every
		// LanguageSupport.ModulePath returns a value rooted at packageName.
		if mod != packageName && !strings.HasPrefix(mod, packageName+".") {
			continue
		}
		syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		for _, s := range syms {
			if !lang.IsExportedSymbol(s) {
				continue
			}
			seen[lang.SymbolKey(mod, s.Name)] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

// collectFilesByExt returns all regular files under root whose names end
// with one of the given extensions. The search is recursive.
func collectFilesByExt(root string, exts []string) ([]string, error) {
	extSet := make(map[string]struct{}, len(exts))
	for _, e := range exts {
		extSet[e] = struct{}{}
	}
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if _, ok := extSet[filepath.Ext(path)]; ok {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
