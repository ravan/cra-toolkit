// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package rust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	grammarrust "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/rust"
)

// ErrNoLibraryAPI indicates the crate has no lib.rs — i.e. it is a binary-
// only crate. The transitive analyzer translates this into the
// ReasonNoLibraryAPI degradation.
var ErrNoLibraryAPI = errors.New("rust crate has no library API")

// ListExports enumerates the deduplicated set of dotted symbol keys by
// which downstream Rust code can reach every exported item in the crate at
// sourceDir. See section 4 of
// docs/superpowers/specs/2026-04-11-rust-transitive-language-support-design.md
// for the full algorithm.
func (l *Language) ListExports(sourceDir, packageName string) ([]string, error) {
	crateRoot, libRS, err := findLibRS(sourceDir, packageName)
	if err != nil {
		return nil, err
	}

	modules, err := walkModuleTree(crateRoot, libRS)
	if err != nil {
		return nil, err
	}

	// Canonical emission and re-export resolution land in later tasks.
	// Stage-by-stage TDD: for now, emit a single key per public module's
	// top-level `pub fn` items using a direct tree-sitter scan.
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(grammarrust.Language())); err != nil {
		return nil, err
	}

	keys := make(map[string]struct{})
	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, err := os.ReadFile(m.file)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		root := tree.RootNode()
		collectTopLevelPublicFns(root, src, packageName, m.path, keys)
		tree.Close()
	}

	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	return out, nil
}

// moduleNode is one entry in the public-accessibility-walked module tree.
type moduleNode struct {
	// path is the dotted module path relative to the crate root. The root
	// itself has an empty string.
	path string
	// file is the absolute source file implementing this module.
	file string
	// isPublic is true when every ancestor in the chain was declared with
	// `pub mod`. Private modules are still walked (for the re-export
	// analysis added in Task 15), but their symbols are not emitted.
	isPublic bool
}

// findLibRS returns the crate root directory (containing Cargo.toml) and
// the absolute path to src/lib.rs. It searches for a `<name>-<version>/`
// subdirectory of sourceDir first — that's how CratesFetcher unpacks — and
// falls back to sourceDir itself for test fixtures that use a flat layout.
func findLibRS(sourceDir, packageName string) (crateRoot, libRS string, err error) { //nolint:nonamedreturns
	// Preferred layout: sourceDir/<name>-<version>/src/lib.rs
	entries, readErr := os.ReadDir(sourceDir)
	if readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if !strings.HasPrefix(entry.Name(), packageName+"-") {
				continue
			}
			candidate := filepath.Join(sourceDir, entry.Name(), "src", "lib.rs")
			if _, statErr := os.Stat(candidate); statErr == nil {
				return filepath.Join(sourceDir, entry.Name()), candidate, nil
			}
		}
	}
	// Fallback: sourceDir/src/lib.rs
	candidate := filepath.Join(sourceDir, "src", "lib.rs")
	if _, statErr := os.Stat(candidate); statErr == nil {
		return sourceDir, candidate, nil
	}
	return "", "", ErrNoLibraryAPI
}

// walkModuleTree walks from libRS through every `mod foo;` / `pub mod foo;`
// declaration, returning every file-backed module node reachable from the
// crate root.
func walkModuleTree(crateRoot, libRS string) ([]moduleNode, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(grammarrust.Language())); err != nil {
		return nil, err
	}

	visited := make(map[string]bool)
	root := moduleNode{path: "", file: libRS, isPublic: true}
	result := []moduleNode{root}
	visited[libRS] = true

	queue := []moduleNode{root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		src, err := os.ReadFile(node.file)
		if err != nil {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		for _, child := range findModDecls(tree.RootNode(), src, node, crateRoot) {
			if visited[child.file] {
				continue
			}
			visited[child.file] = true
			result = append(result, child)
			queue = append(queue, child)
		}
		tree.Close()
	}
	return result, nil
}

// findModDecls returns the child module nodes declared in parent's source.
func findModDecls(root *tree_sitter.Node, src []byte, parent moduleNode, crateRoot string) []moduleNode {
	_ = crateRoot
	var out []moduleNode
	walkTopLevel(root, func(node *tree_sitter.Node) {
		if node.Kind() != "mod_item" {
			return
		}
		name := modItemName(node, src)
		if name == "" {
			return
		}
		isPub := parent.isPublic && isPubVis(node, src)
		// Inline mod: has a declaration_list child. Skip for tree-walker.
		if hasDeclarationList(node) {
			return
		}
		// File-backed mod: try <parentDir>/<name>.rs, then
		// <parentDir>/<name>/mod.rs.
		parentDir := filepath.Dir(parent.file)
		parentBase := filepath.Base(parent.file)
		if parentBase != "lib.rs" && parentBase != "main.rs" && parentBase != "mod.rs" {
			parentName := strings.TrimSuffix(parentBase, ".rs")
			parentDir = filepath.Join(parentDir, parentName)
		}

		candidates := []string{
			filepath.Join(parentDir, name+".rs"),
			filepath.Join(parentDir, name, "mod.rs"),
		}
		var file string
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				file = c
				break
			}
		}
		if file == "" {
			return
		}

		childPath := name
		if parent.path != "" {
			childPath = parent.path + "." + name
		}
		out = append(out, moduleNode{
			path:     childPath,
			file:     file,
			isPublic: isPub,
		})
	})
	return out
}

// walkTopLevel applies fn to every direct child of root (source_file).
func walkTopLevel(root *tree_sitter.Node, fn func(*tree_sitter.Node)) {
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		fn(child)
	}
}

// modItemName returns the identifier name of a mod_item node.
func modItemName(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return child.Utf8Text(src)
		}
	}
	return ""
}

// isPubVis reports whether node has a visibility_modifier whose text is "pub".
func isPubVis(node *tree_sitter.Node, src []byte) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "visibility_modifier" {
			continue
		}
		if strings.TrimSpace(child.Utf8Text(src)) == "pub" {
			return true
		}
	}
	return false
}

// hasDeclarationList reports whether a mod_item has an inline body.
func hasDeclarationList(node *tree_sitter.Node) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "declaration_list" {
			return true
		}
	}
	return false
}

// collectTopLevelPublicFns appends a canonical key for every direct-child
// `pub fn` in root to keys. This is a placeholder for the full canonical-
// emission pass added in Task 14.
func collectTopLevelPublicFns(root *tree_sitter.Node, src []byte, packageName, modPath string, keys map[string]struct{}) {
	base := packageName
	if modPath != "" {
		base = packageName + "." + modPath
	}
	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil || node.Kind() != "function_item" {
			continue
		}
		if !isPubVis(node, src) {
			continue
		}
		name := findFnName(node, src)
		if name == "" {
			continue
		}
		keys[base+"."+name] = struct{}{}
	}
}

// findFnName returns the identifier child of a function_item node.
func findFnName(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return child.Utf8Text(src)
		}
	}
	return ""
}
