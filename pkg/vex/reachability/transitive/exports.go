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
// fully-qualified symbol IDs of the form "<packageName>.<symbolName>".
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
			seen[packageName+"."+s.Name] = struct{}{}
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
