// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	grammarjs "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/javascript"
	grammarpython "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	jsextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/javascript"
	pyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/python"
)

// listExportedSymbols extracts the public API of a package at sourceDir as
// fully-qualified symbol IDs of the form "<module>.<symbolName>" where module
// is derived from the file's path relative to sourceDir. For example, a
// symbol "PoolManager" in "urllib3/poolmanager.py" becomes
// "urllib3.poolmanager.PoolManager".
func listExportedSymbols(language, sourceDir, packageName string) ([]string, error) {
	switch language {
	case "python":
		return listExportedPython(sourceDir, packageName)
	case "javascript", "js":
		return listExportedJavaScript(sourceDir, packageName)
	}
	return nil, nil
}

//nolint:gocognit,gocyclo // parse-and-collect pattern; splitting further would obscure intent
func listExportedPython(sourceDir, packageName string) ([]string, error) {
	files, err := collectFilesByExt(sourceDir, []string{".py"})
	if err != nil {
		return nil, err
	}
	parsed, _ := treesitter.ParseFiles(files, grammarpython.Language())
	defer func() {
		for _, pr := range parsed {
			pr.Tree.Close()
		}
	}()
	ext := pyextractor.New()
	seen := make(map[string]struct{})
	for _, pr := range parsed {
		mod := modulePrefix(pr.File, sourceDir, packageName)
		// Skip files outside the package itself (tests, docs, examples).
		// A valid package module starts with "packageName." or equals "packageName".
		if mod != packageName && !strings.HasPrefix(mod, packageName+".") {
			continue
		}
		syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		for _, s := range syms {
			if strings.HasPrefix(s.Name, "_") {
				continue // private by Python convention
			}
			if s.Kind != treesitter.SymbolFunction && s.Kind != treesitter.SymbolMethod && s.Kind != treesitter.SymbolClass {
				continue
			}
			seen[mod+"."+s.Name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

func listExportedJavaScript(sourceDir, packageName string) ([]string, error) {
	files, err := collectFilesByExt(sourceDir, []string{".js", ".mjs", ".cjs"})
	if err != nil {
		return nil, err
	}
	parsed, _ := treesitter.ParseFiles(files, grammarjs.Language())
	defer func() {
		for _, pr := range parsed {
			pr.Tree.Close()
		}
	}()
	ext := jsextractor.New()
	seen := make(map[string]struct{})
	for _, pr := range parsed {
		mod := modulePrefix(pr.File, sourceDir, packageName)
		// Skip files outside the package itself (tests, examples, scripts).
		if mod != packageName && !strings.HasPrefix(mod, packageName+".") {
			continue
		}
		syms, err := ext.ExtractSymbols(pr.File, pr.Source, pr.Tree)
		if err != nil {
			continue
		}
		for _, s := range syms {
			if s.Kind != treesitter.SymbolFunction && s.Kind != treesitter.SymbolMethod && s.Kind != treesitter.SymbolClass {
				continue
			}
			seen[packageName+"."+s.Name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out, nil
}

// modulePrefix derives the dotted module path for a file from its path
// relative to sourceDir. It searches for the first path component that
// exactly matches packageName, then uses everything from that component
// onward. This correctly handles both flat and src-layout tarballs:
//
//   - Flat:       "urllib3-1.26/urllib3/poolmanager.py"   → "urllib3.poolmanager"
//   - Src layout: "urllib3-2.0.5/src/urllib3/util/retry.py" → "urllib3.util.retry"
//
// If no component matches packageName, falls back to the full relative
// path (test files and other non-package paths).
func modulePrefix(file, sourceDir, packageName string) string {
	rel, err := filepath.Rel(sourceDir, file)
	if err != nil {
		return packageName
	}
	// Strip the file extension and split into path components.
	rel = strings.TrimSuffix(rel, filepath.Ext(rel))
	parts := strings.Split(rel, string(filepath.Separator))

	// Find the first component that exactly matches the package name.
	// This skips version-suffixed tarball directories (e.g., "urllib3-2.0.5")
	// and src-layout prefix directories (e.g., "src").
	for i, part := range parts {
		if part == packageName {
			mod := strings.Join(parts[i:], ".")
			mod = strings.TrimSuffix(mod, ".__init__")
			mod = strings.TrimSuffix(mod, ".__main__")
			return mod
		}
	}

	// Fallback: join all parts (e.g., for test/ or contrib/ files outside the
	// package directory — these become noise targets that won't match any scope).
	mod := strings.Join(parts, ".")
	mod = strings.TrimSuffix(mod, ".__init__")
	mod = strings.TrimSuffix(mod, ".__main__")
	return mod
}

// collectFilesByExt returns all regular files under root whose names end with
// one of the given extensions. The search is recursive.
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
