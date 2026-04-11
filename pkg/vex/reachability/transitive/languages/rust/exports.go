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

	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(grammarrust.Language())); err != nil {
		return nil, err
	}

	// Pass 1: collect public type names (for trait-impl gating).
	publicTypes := make(map[string]bool)
	sources := make(map[string][]byte, len(modules))

	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, err := os.ReadFile(m.file)
		if err != nil {
			continue
		}
		sources[m.file] = src
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		collectPublicTypeNames(tree.RootNode(), src, packageName, m.path, publicTypes)
		tree.Close()
	}

	// Pass 2: emit canonical keys.
	keys := make(map[string]struct{})
	canonicalByName := make(map[string]string)

	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, ok := sources[m.file]
		if !ok {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		emitCanonicalRecord(tree.RootNode(), src, packageName, m.path, publicTypes, keys, canonicalByName)
		tree.Close()
	}

	// Pass 3: re-export collection.
	var edges []reExportEdge
	for _, m := range modules {
		if !m.isPublic {
			continue
		}
		src, ok := sources[m.file]
		if !ok {
			continue
		}
		tree := parser.Parse(src, nil)
		if tree == nil {
			continue
		}
		edges = append(edges, collectPubUseEdges(tree.RootNode(), src, packageName, m.path, canonicalByName)...)
		tree.Close()
	}

	// Pass 4: fixed-point chain resolution.
	publicPaths := make(map[string]map[string]struct{})
	for _, e := range edges {
		if _, ok := publicPaths[e.canonical]; !ok {
			publicPaths[e.canonical] = make(map[string]struct{})
		}
		publicPaths[e.canonical][e.publicPath] = struct{}{}
	}
	for changed := true; changed; {
		changed = false
		for canonicalA, pathsA := range publicPaths {
			for p := range pathsA {
				if pathsA2, ok := publicPaths[p]; ok && p != canonicalA {
					for p2 := range pathsA2 {
						if _, exists := publicPaths[canonicalA][p2]; !exists {
							publicPaths[canonicalA][p2] = struct{}{}
							changed = true
						}
					}
				}
			}
		}
	}

	for _, paths := range publicPaths {
		for p := range paths {
			keys[p] = struct{}{}
		}
	}

	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	return out, nil
}

type reExportEdge struct {
	publicPath string
	canonical  string
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

// basePath builds the dotted prefix for a module.
func basePath(packageName, modPath string) string {
	if modPath == "" {
		return packageName
	}
	return packageName + "." + modPath
}

// collectPublicTypeNames collects struct/enum/trait names into publicTypes.
func collectPublicTypeNames(root *tree_sitter.Node, src []byte, packageName, modPath string, publicTypes map[string]bool) {
	base := basePath(packageName, modPath)
	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil {
			continue
		}
		switch node.Kind() {
		case "struct_item", "enum_item", "trait_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findTypeIdent(node, src)
			if name == "" {
				continue
			}
			publicTypes[base+"."+name] = true
		}
	}
}

// findTypeIdent returns the type_identifier child of a node.
func findTypeIdent(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "type_identifier" {
			return child.Utf8Text(src)
		}
	}
	return ""
}

// emitCanonicalRecord emits canonical keys for all public symbols in root,
// populating canonicalByName for re-export resolution.
//
//nolint:gocognit,gocyclo
func emitCanonicalRecord(
	root *tree_sitter.Node,
	src []byte,
	packageName, modPath string,
	publicTypes map[string]bool,
	keys map[string]struct{},
	canonicalByName map[string]string,
) {
	base := basePath(packageName, modPath)
	record := func(key string) {
		keys[key] = struct{}{}
		if strings.HasPrefix(key, packageName+".") {
			canonicalByName[key[len(packageName)+1:]] = key
		} else if key == packageName {
			canonicalByName[""] = key
		}
	}

	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil {
			continue
		}
		switch node.Kind() {
		case "function_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findFnName(node, src)
			if name != "" {
				record(base + "." + name)
			}
		case "struct_item", "enum_item":
			if !isPubVis(node, src) {
				continue
			}
			name := findTypeIdent(node, src)
			if name != "" {
				record(base + "." + name)
			}
		case "trait_item":
			if !isPubVis(node, src) {
				continue
			}
			traitName := findTypeIdent(node, src)
			if traitName == "" {
				continue
			}
			record(base + "." + traitName)
			for i2 := uint(0); i2 < node.ChildCount(); i2++ {
				body := node.Child(i2)
				if body == nil || body.Kind() != "declaration_list" {
					continue
				}
				for j := uint(0); j < body.ChildCount(); j++ {
					item := body.Child(j)
					if item == nil {
						continue
					}
					if item.Kind() == "function_signature_item" || item.Kind() == "function_item" {
						mn := findFnName(item, src)
						if mn != "" {
							record(base + "." + traitName + "." + mn)
						}
					}
				}
			}
		case "impl_item":
			emitImplRecord(node, src, base, publicTypes, record)
		}
	}
}

// emitImplRecord emits method keys for an impl block, gated on publicTypes.
func emitImplRecord(node *tree_sitter.Node, src []byte, base string, publicTypes map[string]bool, record func(string)) {
	var traitName, typeName string
	hasFOR := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "type_identifier":
			if typeName == "" && traitName == "" {
				typeName = child.Utf8Text(src)
			} else if hasFOR {
				typeName = child.Utf8Text(src)
			}
		case "for":
			hasFOR = true
			traitName = typeName
			typeName = ""
		}
	}
	if typeName == "" {
		return
	}
	isTraitImpl := traitName != ""
	typeKey := base + "." + typeName
	if !publicTypes[typeKey] {
		return
	}
	for i := uint(0); i < node.ChildCount(); i++ {
		body := node.Child(i)
		if body == nil || body.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < body.ChildCount(); j++ {
			item := body.Child(j)
			if item == nil || item.Kind() != "function_item" {
				continue
			}
			mn := findFnName(item, src)
			if mn == "" {
				continue
			}
			if isTraitImpl || isPubVis(item, src) {
				record(typeKey + "." + mn)
			}
		}
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

// collectPubUseEdges collects re-export edges from pub use declarations.
func collectPubUseEdges(
	root *tree_sitter.Node,
	src []byte,
	packageName, modPath string,
	canonicalByName map[string]string,
) []reExportEdge {
	var edges []reExportEdge
	base := basePath(packageName, modPath)

	for i := uint(0); i < root.ChildCount(); i++ {
		node := root.Child(i)
		if node == nil || node.Kind() != "use_declaration" {
			continue
		}
		if !isPubVis(node, src) {
			continue
		}
		for j := uint(0); j < node.ChildCount(); j++ {
			body := node.Child(j)
			if body == nil {
				continue
			}
			switch body.Kind() {
			case "scoped_identifier":
				fullPath := body.Utf8Text(src)
				publicAlias := lastPathSegment(fullPath)
				edges = appendResolvedReExport(edges, fullPath, publicAlias,
					packageName, modPath, base, canonicalByName)
			case "scoped_use_list":
				edges = append(edges, resolveUseList(body, src, packageName, modPath, base, canonicalByName)...)
			case "use_as_clause":
				edges = append(edges, resolveUseAs(body, src, packageName, modPath, base, canonicalByName)...)
			case "use_wildcard":
				edges = append(edges, resolveUseWildcard(body, src, packageName, modPath, base, canonicalByName)...)
			case "identifier":
				name := body.Utf8Text(src)
				edges = appendResolvedReExport(edges, name, name,
					packageName, modPath, base, canonicalByName)
			}
		}
	}
	return edges
}

// lastPathSegment returns the last `::` segment of a Rust path.
func lastPathSegment(path string) string {
	if idx := strings.LastIndex(path, "::"); idx >= 0 {
		return path[idx+2:]
	}
	return path
}

// resolveRelativePath converts a Rust path to a dotted relative name.
func resolveRelativePath(path, packageName, modPath string) (string, bool) {
	p := strings.ReplaceAll(path, "::", ".")
	switch {
	case strings.HasPrefix(p, "crate."):
		return p[len("crate."):], true
	case p == "crate":
		return "", true
	case strings.HasPrefix(p, "self."):
		rest := p[len("self."):]
		if modPath == "" {
			return rest, true
		}
		return modPath + "." + rest, true
	case strings.HasPrefix(p, "super."):
		parentMod := parentModulePath(modPath)
		rest := p[len("super."):]
		if parentMod == "" {
			return rest, true
		}
		return parentMod + "." + rest, true
	}
	if strings.HasPrefix(p, packageName+".") {
		return p[len(packageName)+1:], true
	}
	return p, true
}

// parentModulePath returns the parent module path (strips last segment).
func parentModulePath(modPath string) string {
	if modPath == "" {
		return ""
	}
	if idx := strings.LastIndex(modPath, "."); idx >= 0 {
		return modPath[:idx]
	}
	return ""
}

// appendResolvedReExport resolves a re-export source path and appends an edge.
func appendResolvedReExport(
	edges []reExportEdge,
	sourcePath, publicAlias, packageName, modPath, base string,
	canonicalByName map[string]string,
) []reExportEdge {
	relLookup, ok := resolveRelativePath(sourcePath, packageName, modPath)
	if !ok {
		return edges
	}
	canonicalKey, known := canonicalByName[relLookup]
	if !known {
		return edges
	}
	publicPath := base + "." + publicAlias
	return append(edges, reExportEdge{publicPath: publicPath, canonical: canonicalKey})
}

// resolveUseList handles `pub use prefix::{A, B, C}` imports.
func resolveUseList(
	node *tree_sitter.Node,
	src []byte,
	packageName, modPath, base string,
	canonicalByName map[string]string,
) []reExportEdge {
	var prefix string
	var edges []reExportEdge
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "scoped_identifier", "identifier", "crate":
			prefix = child.Utf8Text(src)
		case "use_list":
			for j := uint(0); j < child.ChildCount(); j++ {
				item := child.Child(j)
				if item == nil {
					continue
				}
				switch item.Kind() {
				case "identifier":
					name := item.Utf8Text(src)
					edges = appendResolvedReExport(edges, prefix+"::"+name, name,
						packageName, modPath, base, canonicalByName)
				case "scoped_identifier":
					full := item.Utf8Text(src)
					alias := lastPathSegment(full)
					edges = appendResolvedReExport(edges, prefix+"::"+full, alias,
						packageName, modPath, base, canonicalByName)
				case "use_as_clause":
					inner, rename := extractUseAsInner(item, src)
					if inner == "" {
						continue
					}
					edges = appendResolvedReExport(edges, prefix+"::"+inner, rename,
						packageName, modPath, base, canonicalByName)
				}
			}
		}
	}
	return edges
}

// extractUseAsInner extracts the inner path and alias from a use_as_clause.
func extractUseAsInner(node *tree_sitter.Node, src []byte) (string, string) {
	var inner, alias string
	sawAs := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "scoped_identifier":
			inner = child.Utf8Text(src)
		case "as":
			sawAs = true
		case "identifier":
			if sawAs {
				alias = child.Utf8Text(src)
			} else if inner == "" {
				inner = child.Utf8Text(src)
			}
		}
	}
	if alias == "" {
		alias = lastPathSegment(inner)
	}
	return inner, alias
}

// resolveUseAs handles `pub use path::Thing as Alias` imports.
func resolveUseAs(
	node *tree_sitter.Node,
	src []byte,
	packageName, modPath, base string,
	canonicalByName map[string]string,
) []reExportEdge {
	inner, alias := extractUseAsInner(node, src)
	if inner == "" {
		return nil
	}
	return appendResolvedReExport(nil, inner, alias,
		packageName, modPath, base, canonicalByName)
}

// resolveUseWildcard handles `pub use path::*` imports.
func resolveUseWildcard(
	node *tree_sitter.Node,
	src []byte,
	packageName, modPath, base string,
	canonicalByName map[string]string,
) []reExportEdge {
	var prefixRaw string
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "scoped_identifier" || child.Kind() == "identifier" {
			prefixRaw = child.Utf8Text(src)
			break
		}
	}
	if prefixRaw == "" {
		return nil
	}
	rel, ok := resolveRelativePath(prefixRaw, packageName, modPath)
	if !ok {
		return nil
	}
	var edges []reExportEdge
	relPrefix := rel + "."
	for canonicalRel, canonicalFull := range canonicalByName {
		if !strings.HasPrefix(canonicalRel, relPrefix) {
			continue
		}
		tail := canonicalRel[len(relPrefix):]
		if strings.Contains(tail, ".") {
			continue
		}
		publicPath := base + "." + tail
		edges = append(edges, reExportEdge{publicPath: publicPath, canonical: canonicalFull})
	}
	return edges
}
