// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package rust implements tree-sitter AST extraction for Rust source files.
// It extracts symbols (functions, methods, structs, enums, traits), imports,
// and call edges. Trait-impl analysis (CHA analogue for Rust) is performed
// to resolve dynamic dispatch through &dyn Trait parameters.
package rust

import (
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// Compile-time interface conformance check.
var _ treesitter.LanguageExtractor = (*Extractor)(nil)

// paramKey identifies a single parameter for trait dispatch resolution.
type paramKey struct {
	function, param string
}

// Extractor extracts symbols, imports, and call edges from Rust ASTs.
// It builds a trait-impl map for dynamic dispatch resolution (analogous to Java CHA).
type Extractor struct {
	// traitImpls maps trait name → slice of concrete implementor type names.
	// E.g. "Handler" → ["LogHandler", "FileHandler"]
	traitImpls map[string][]string

	// methodToTypes maps method name → slice of type names that define it.
	methodToTypes map[string][]string

	// paramTypes maps (function qualified name, param name) → param type name.
	// Used for trait dispatch: when a function takes &dyn Trait, we record it.
	paramTypes map[paramKey]string
}

// New creates a new Rust Extractor.
func New() *Extractor {
	return &Extractor{
		traitImpls:    make(map[string][]string),
		methodToTypes: make(map[string][]string),
		paramTypes:    make(map[paramKey]string),
	}
}

// nodeText returns the UTF-8 text of a node.
func nodeText(n *tree_sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(src)
}

// rowToLine converts a tree-sitter 0-based row to a 1-based line number.
func rowToLine(row uint) int {
	return int(row) + 1 //nolint:gosec // row is a line number, never overflows int
}

// moduleFromFile derives the Rust module name from a file path.
// main.rs/lib.rs/mod.rs → parent directory name; other files → filename without extension.
func moduleFromFile(file string) string {
	base := filepath.Base(file)
	switch base {
	case "main.rs", "lib.rs", "mod.rs":
		dir := filepath.Dir(file)
		return filepath.Base(dir)
	default:
		return strings.TrimSuffix(base, ".rs")
	}
}

// appendUnique appends value to slice only if not already present.
func appendUnique(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// qualifyName builds a dot-separated qualified name from non-empty parts.
func qualifyName(parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, ".")
}

// isPubVisibility reports whether node has a direct visibility_modifier child
// whose literal text is exactly "pub" (not "pub(crate)", "pub(super)", or
// "pub(in path)"). A trimmed equality check handles grammars that include
// trailing whitespace in the modifier's text span.
func isPubVisibility(node *tree_sitter.Node, src []byte) bool {
	if node == nil {
		return false
	}
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "visibility_modifier" {
			continue
		}
		if strings.TrimSpace(nodeText(child, src)) == "pub" {
			return true
		}
	}
	return false
}

// stripRefWrappers strips reference wrappers from a type string:
// &, &mut, Box<T>, Arc<T>, Rc<T>, dyn Trait → inner type.
func stripRefWrappers(typeName string) string {
	// Strip leading & and &mut
	typeName = strings.TrimPrefix(typeName, "&mut ")
	typeName = strings.TrimPrefix(typeName, "&")
	typeName = strings.TrimSpace(typeName)

	// Strip "dyn " prefix
	typeName = strings.TrimPrefix(typeName, "dyn ")
	typeName = strings.TrimSpace(typeName)

	// Strip wrapper types: Box<T>, Arc<T>, Rc<T>
	for _, wrapper := range []string{"Box<", "Arc<", "Rc<"} {
		if strings.HasPrefix(typeName, wrapper) && strings.HasSuffix(typeName, ">") {
			typeName = typeName[len(wrapper) : len(typeName)-1]
			typeName = strings.TrimSpace(typeName)
			// Recurse to handle nested wrappers like Box<dyn Handler>
			typeName = stripRefWrappers(typeName)
		}
	}

	return typeName
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractSymbols
// ─────────────────────────────────────────────────────────────────────────────

// ExtractSymbols walks the Rust AST to find all function, method, struct, enum,
// and trait definitions. It also builds the trait-impl map for dispatch resolution.
func (e *Extractor) ExtractSymbols(file string, src []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	// Reset per-call state
	e.traitImpls = make(map[string][]string)
	e.methodToTypes = make(map[string][]string)
	e.paramTypes = make(map[paramKey]string)

	root := tree.RootNode()
	mod := moduleFromFile(file)

	var symbols []*treesitter.Symbol
	e.walkSymbols(root, src, file, mod, "", &symbols)
	return symbols, nil
}

// walkSymbols recursively visits AST nodes to collect definitions.
//
//nolint:gocognit,gocyclo // AST walker handles many Rust node types
func (e *Extractor) walkSymbols(
	node *tree_sitter.Node,
	src []byte,
	file, mod, currentType string,
	symbols *[]*treesitter.Symbol,
) {
	if node == nil {
		return
	}

	kind := node.Kind()

	switch kind {
	case "function_item":
		e.extractFunction(node, src, file, mod, currentType, isPubVisibility(node, src), symbols)
		return

	case "struct_item":
		e.extractTypeDefNode(node, src, file, mod, "type_identifier", isPubVisibility(node, src), symbols)
		return

	case "enum_item":
		e.extractTypeDefNode(node, src, file, mod, "type_identifier", isPubVisibility(node, src), symbols)
		return

	case "trait_item":
		e.extractTrait(node, src, file, mod, symbols)
		return

	case "impl_item":
		e.extractImpl(node, src, file, mod, symbols)
		return

	case "mod_item":
		// Recurse into mod body, but don't change module name for now
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child != nil && child.Kind() == "declaration_list" {
				for j := uint(0); j < child.ChildCount(); j++ {
					e.walkSymbols(child.Child(j), src, file, mod, currentType, symbols)
				}
			}
		}
		return
	}

	// Recurse into children
	for i := uint(0); i < node.ChildCount(); i++ {
		e.walkSymbols(node.Child(i), src, file, mod, currentType, symbols)
	}
}

// extractFunction processes a function_item node.
func (e *Extractor) extractFunction(
	node *tree_sitter.Node,
	src []byte,
	file, mod, currentType string,
	isPublic bool,
	symbols *[]*treesitter.Symbol,
) {
	name := findChildIdentifier(node, src)
	if name == "" {
		return
	}

	symKind := treesitter.SymbolFunction
	qualifiedName := qualifyName(mod, name)
	if currentType != "" {
		symKind = treesitter.SymbolMethod
		qualifiedName = qualifyName(mod, currentType, name)
	}

	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "rust",
		File:          file,
		Package:       mod,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          symKind,
		IsPublic:      isPublic,
	}
	*symbols = append(*symbols, sym)

	// Register method→type mapping for dispatch resolution
	if currentType != "" {
		e.methodToTypes[name] = appendUnique(e.methodToTypes[name], currentType)
	}

	// Collect parameter types for trait dispatch
	e.collectParamTypes(node, src, qualifiedName)
}

// collectParamTypes extracts parameter names and types from a function_item.
// It records parameters with trait object types (e.g. &dyn Handler) for dispatch.
//
//nolint:gocognit,gocyclo // three-level parameter node traversal requires nested loops
func (e *Extractor) collectParamTypes(node *tree_sitter.Node, src []byte, funcQualified string) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "parameters" {
			continue
		}
		for j := uint(0); j < child.ChildCount(); j++ {
			param := child.Child(j)
			if param == nil || param.Kind() != "parameter" {
				continue
			}
			paramName := ""
			paramType := ""
			for k := uint(0); k < param.ChildCount(); k++ {
				pChild := param.Child(k)
				if pChild == nil {
					continue
				}
				switch pChild.Kind() {
				case "identifier":
					paramName = nodeText(pChild, src)
				case "reference_type", "type_identifier", "scoped_type_identifier",
					"generic_type", "dynamic_type":
					paramType = nodeText(pChild, src)
				}
			}
			if paramName != "" && paramType != "" {
				stripped := stripRefWrappers(paramType)
				key := paramKey{function: funcQualified, param: paramName}
				e.paramTypes[key] = stripped
			}
		}
	}
}

// extractTypeDefNode processes a struct_item or enum_item node.
func (e *Extractor) extractTypeDefNode(
	node *tree_sitter.Node,
	src []byte,
	file, mod, _ string,
	isPublic bool,
	symbols *[]*treesitter.Symbol,
) {
	name := findChildTypeIdentifier(node, src)
	if name == "" {
		return
	}

	qualifiedName := qualifyName(mod, name)
	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "rust",
		File:          file,
		Package:       mod,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
		IsPublic:      isPublic,
	}
	*symbols = append(*symbols, sym)
}

// extractTrait processes a trait_item node. Extracts the trait as SymbolClass
// and its method signatures as SymbolMethod.
//
//nolint:gocognit // trait body traversal for method signatures requires nested iteration
func (e *Extractor) extractTrait(
	node *tree_sitter.Node,
	src []byte,
	file, mod string,
	symbols *[]*treesitter.Symbol,
) {
	traitName := findChildTypeIdentifier(node, src)
	if traitName == "" {
		return
	}

	traitIsPublic := isPubVisibility(node, src)

	qualifiedName := qualifyName(mod, traitName)
	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          traitName,
		QualifiedName: qualifiedName,
		Language:      "rust",
		File:          file,
		Package:       mod,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
		IsPublic:      traitIsPublic,
	}
	*symbols = append(*symbols, sym)

	// Extract method signatures from the trait body (declaration_list)
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < child.ChildCount(); j++ {
			item := child.Child(j)
			if item == nil {
				continue
			}
			switch item.Kind() {
			case "function_signature_item":
				methodName := findChildIdentifier(item, src)
				if methodName == "" {
					continue
				}
				mQualified := qualifyName(mod, traitName, methodName)
				mID := treesitter.SymbolID(mQualified)
				mSym := &treesitter.Symbol{
					ID:            mID,
					Name:          methodName,
					QualifiedName: mQualified,
					Language:      "rust",
					File:          file,
					Package:       mod,
					StartLine:     rowToLine(item.StartPosition().Row),
					EndLine:       rowToLine(item.EndPosition().Row),
					Kind:          treesitter.SymbolMethod,
					IsPublic:      traitIsPublic,
				}
				*symbols = append(*symbols, mSym)
				e.methodToTypes[methodName] = appendUnique(e.methodToTypes[methodName], traitName)

			case "function_item":
				// Default trait method body — inherits trait visibility.
				e.extractFunction(item, src, file, mod, traitName, traitIsPublic, symbols)
			}
		}
	}
}

// extractImpl processes an impl_item node. Handles both:
//   - `impl Type { ... }` (inherent impl)
//   - `impl Trait for Type { ... }` (trait impl)
//
//nolint:gocognit,gocyclo // impl detection requires checking for "for" keyword and iterating children
func (e *Extractor) extractImpl(
	node *tree_sitter.Node,
	src []byte,
	file, mod string,
	symbols *[]*treesitter.Symbol,
) {
	// Parse the impl header to determine if it's a trait impl.
	// impl_item children: "impl" [type_identifier (trait)] "for" type_identifier (type) declaration_list
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
				// First type_identifier: could be trait or type
				typeName = nodeText(child, src)
			} else if hasFOR {
				// After "for": this is the implementing type
				typeName = nodeText(child, src)
			}
		case "generic_type", "scoped_type_identifier":
			if typeName == "" && traitName == "" {
				typeName = extractSimpleTypeName(child, src)
			} else if hasFOR {
				typeName = extractSimpleTypeName(child, src)
			}
		case "for":
			// This is "impl Trait for Type" — the first type was actually the trait
			hasFOR = true
			traitName = typeName
			typeName = "" // will be set by the next type_identifier
		}
	}

	if typeName == "" {
		return
	}

	// Record trait→implementor mapping
	if traitName != "" {
		e.traitImpls[traitName] = appendUnique(e.traitImpls[traitName], typeName)
	}

	// Extract methods from the impl body
	isTraitImpl := traitName != ""
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "declaration_list" {
			continue
		}
		for j := uint(0); j < child.ChildCount(); j++ {
			item := child.Child(j)
			if item != nil && item.Kind() == "function_item" {
				isPublic := isTraitImpl || isPubVisibility(item, src)
				e.extractFunction(item, src, file, mod, typeName, isPublic, symbols)
			}
		}
	}
}

// findChildIdentifier returns the text of the first direct "identifier" child.
func findChildIdentifier(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return nodeText(child, src)
		}
	}
	return ""
}

// findChildTypeIdentifier returns the text of the first direct "type_identifier" child.
func findChildTypeIdentifier(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "type_identifier" {
			return nodeText(child, src)
		}
	}
	return ""
}

// extractSimpleTypeName returns the simple type name from a potentially complex type node.
func extractSimpleTypeName(node *tree_sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	text := nodeText(node, src)
	// Handle generics: "Vec<String>" → "Vec"
	if idx := strings.IndexByte(text, '<'); idx > 0 {
		text = text[:idx]
	}
	// Handle scoped: "std::io::Read" → "Read"
	if idx := strings.LastIndex(text, "::"); idx >= 0 {
		text = text[idx+2:]
	}
	return strings.TrimSpace(text)
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait-Impl Snapshot / Restore
// ─────────────────────────────────────────────────────────────────────────────

// TraitImplSnapshot captures the cross-file trait-impl state for restoration.
type TraitImplSnapshot struct {
	traitImpls    map[string][]string
	methodToTypes map[string][]string
	paramTypes    map[paramKey]string
}

// SnapshotTraitImpls captures the current trait-impl state so it can be restored
// after per-file ExtractSymbols calls reset the extractor's state.
func (e *Extractor) SnapshotTraitImpls() *TraitImplSnapshot {
	snap := &TraitImplSnapshot{
		traitImpls:    make(map[string][]string, len(e.traitImpls)),
		methodToTypes: make(map[string][]string, len(e.methodToTypes)),
		paramTypes:    make(map[paramKey]string, len(e.paramTypes)),
	}
	for k, v := range e.traitImpls {
		dst := make([]string, len(v))
		copy(dst, v)
		snap.traitImpls[k] = dst
	}
	for k, v := range e.methodToTypes {
		dst := make([]string, len(v))
		copy(dst, v)
		snap.methodToTypes[k] = dst
	}
	for k, v := range e.paramTypes {
		snap.paramTypes[k] = v
	}
	return snap
}

// RestoreTraitImpls merges a snapshot's trait-impl data into the current extractor state.
// Called before ExtractCalls to ensure cross-file trait dispatch is resolved.
func (e *Extractor) RestoreTraitImpls(snap *TraitImplSnapshot) {
	if snap == nil {
		return
	}
	for k, v := range snap.traitImpls {
		for _, impl := range v {
			e.traitImpls[k] = appendUnique(e.traitImpls[k], impl)
		}
	}
	for k, v := range snap.methodToTypes {
		for _, typ := range v {
			e.methodToTypes[k] = appendUnique(e.methodToTypes[k], typ)
		}
	}
	for k, v := range snap.paramTypes {
		if _, exists := e.paramTypes[k]; !exists {
			e.paramTypes[k] = v
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveImports
// ─────────────────────────────────────────────────────────────────────────────

// ResolveImports walks the AST to find all use declarations and extern crate declarations.
func (e *Extractor) ResolveImports(file string, src []byte, tree *tree_sitter.Tree, _ string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import
	collectImports(root, src, file, &imports)
	return imports, nil
}

// collectImports recursively finds use_declaration and extern_crate_declaration nodes.
func collectImports(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	if node == nil {
		return
	}

	switch node.Kind() {
	case "use_declaration":
		extractUseDecl(node, src, file, imports)
		return
	case "extern_crate_declaration":
		extractExternCrate(node, src, file, imports)
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		collectImports(node.Child(i), src, file, imports)
	}
}

// extractUseDecl processes a use_declaration. Handles:
//   - Simple: use std::collections::HashMap;
//   - Grouped: use hyper::{Body, Request};
//   - Aliased: use serde::Serialize as Ser;
//   - Wildcard: use std::io::*;
//
//nolint:gocognit // handles multiple use declaration forms
func extractUseDecl(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	line := rowToLine(node.StartPosition().Row)

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		switch child.Kind() {
		case "scoped_identifier":
			// Simple use: use std::collections::HashMap;
			fullPath := nodeText(child, src)
			alias := lastSegment(fullPath, "::")
			*imports = append(*imports, treesitter.Import{
				Module: fullPath,
				Alias:  alias,
				File:   file,
				Line:   line,
			})
			return

		case "scoped_use_list":
			// Grouped use: use hyper::{Body, Request, Response};
			extractScopedUseList(child, src, file, line, imports)
			return

		case "use_as_clause":
			// Aliased: use serde::Serialize as Ser;
			extractUseAsClause(child, src, file, line, imports)
			return

		case "use_wildcard":
			// Wildcard: use std::io::*;
			extractUseWildcard(child, src, file, line, imports)
			return

		case "identifier":
			// Simple single-segment: use serde; (rare but valid)
			name := nodeText(child, src)
			*imports = append(*imports, treesitter.Import{
				Module: name,
				Alias:  name,
				File:   file,
				Line:   line,
			})
			return
		}
	}
}

// extractScopedUseList processes a scoped_use_list like hyper::{Body, Request}.
//
//nolint:gocognit // handles prefix extraction and use_list iteration
func extractScopedUseList(node *tree_sitter.Node, src []byte, file string, line int, imports *[]treesitter.Import) {
	// Find the prefix (scoped_identifier or identifier before the use_list)
	var prefix string
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "scoped_identifier", "identifier", "crate":
			prefix = nodeText(child, src)
		case "use_list":
			// Extract each item in the use_list
			for j := uint(0); j < child.ChildCount(); j++ {
				item := child.Child(j)
				if item == nil {
					continue
				}
				switch item.Kind() {
				case "identifier":
					name := nodeText(item, src)
					fullPath := prefix + "::" + name
					*imports = append(*imports, treesitter.Import{
						Module: fullPath,
						Alias:  name,
						File:   file,
						Line:   line,
					})
				case "scoped_identifier":
					name := nodeText(item, src)
					fullPath := prefix + "::" + name
					alias := lastSegment(name, "::")
					*imports = append(*imports, treesitter.Import{
						Module: fullPath,
						Alias:  alias,
						File:   file,
						Line:   line,
					})
				}
			}
		}
	}
}

// extractUseAsClause processes a use_as_clause like serde::Serialize as Ser.
func extractUseAsClause(node *tree_sitter.Node, src []byte, file string, line int, imports *[]treesitter.Import) {
	// Children: scoped_identifier "as" identifier
	var modulePath, alias string
	sawAs := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "scoped_identifier":
			modulePath = nodeText(child, src)
		case "as":
			sawAs = true
		case "identifier":
			if sawAs {
				alias = nodeText(child, src)
			} else if modulePath == "" {
				modulePath = nodeText(child, src)
			}
		}
	}

	if modulePath == "" {
		return
	}
	if alias == "" {
		alias = lastSegment(modulePath, "::")
	}

	*imports = append(*imports, treesitter.Import{
		Module: modulePath,
		Alias:  alias,
		File:   file,
		Line:   line,
	})
}

// extractUseWildcard processes a use_wildcard like std::io::*.
func extractUseWildcard(node *tree_sitter.Node, src []byte, file string, line int, imports *[]treesitter.Import) {
	// Children: scoped_identifier "::" "*"
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "scoped_identifier" || child.Kind() == "identifier" {
			modulePath := nodeText(child, src)
			*imports = append(*imports, treesitter.Import{
				Module: modulePath,
				Alias:  modulePath,
				File:   file,
				Line:   line,
			})
			return
		}
	}
}

// extractExternCrate processes an extern_crate_declaration.
func extractExternCrate(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	line := rowToLine(node.StartPosition().Row)
	name := findChildIdentifier(node, src)
	if name == "" {
		return
	}
	*imports = append(*imports, treesitter.Import{
		Module: name,
		Alias:  name,
		File:   file,
		Line:   line,
	})
}

// lastSegment returns the last segment of a path split by the given separator.
func lastSegment(path, sep string) string {
	if idx := strings.LastIndex(path, sep); idx >= 0 {
		return path[idx+len(sep):]
	}
	return path
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractCalls
// ─────────────────────────────────────────────────────────────────────────────

// ExtractCalls walks the AST to find all function/method calls and produces call edges.
// For direct calls, EdgeDirect edges are emitted.
// For calls through &dyn Trait parameters, EdgeDispatch edges are emitted to all
// known implementors with confidence 0.5.
func (e *Extractor) ExtractCalls(file string, src []byte, tree *tree_sitter.Tree, _ *treesitter.Scope) ([]treesitter.Edge, error) {
	root := tree.RootNode()
	mod := moduleFromFile(file)

	var edges []treesitter.Edge
	e.collectCalls(root, src, file, mod, "", &edges)
	return edges, nil
}

// collectCalls recursively visits nodes to find call_expression nodes.
//
//nolint:gocognit,gocyclo // call extraction handles many Rust node structures
func (e *Extractor) collectCalls(
	node *tree_sitter.Node,
	src []byte,
	file, mod, currentFunc string,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	kind := node.Kind()

	switch kind {
	case "function_item":
		// Update current function context
		name := findChildIdentifier(node, src)
		if name != "" {
			// Determine the qualified name based on parent context
			funcQualified := qualifyName(mod, name)
			// Check if this is inside an impl block by looking at currentFunc context
			// For simplicity, walk the body with updated context
			for i := uint(0); i < node.ChildCount(); i++ {
				child := node.Child(i)
				if child != nil && child.Kind() == "block" {
					e.collectCalls(child, src, file, mod, funcQualified, edges)
				}
			}
		}
		return

	case "impl_item":
		// Extract type name for method context
		typeName := extractImplTypeName(node, src)
		if typeName != "" {
			for i := uint(0); i < node.ChildCount(); i++ {
				child := node.Child(i)
				if child == nil || child.Kind() != "declaration_list" {
					continue
				}
				for j := uint(0); j < child.ChildCount(); j++ {
					item := child.Child(j)
					if item == nil || item.Kind() != "function_item" {
						continue
					}
					methodName := findChildIdentifier(item, src)
					if methodName == "" {
						continue
					}
					methodQualified := qualifyName(mod, typeName, methodName)
					for k := uint(0); k < item.ChildCount(); k++ {
						block := item.Child(k)
						if block != nil && block.Kind() == "block" {
							e.collectCalls(block, src, file, mod, methodQualified, edges)
						}
					}
				}
			}
		}
		return

	case "call_expression":
		e.processCallExpression(node, src, file, mod, currentFunc, edges)
		// Recurse into arguments for nested calls
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child != nil && child.Kind() == "arguments" {
				e.collectCalls(child, src, file, mod, currentFunc, edges)
			}
		}
		return
	}

	// Recurse into all children
	for i := uint(0); i < node.ChildCount(); i++ {
		e.collectCalls(node.Child(i), src, file, mod, currentFunc, edges)
	}
}

// processCallExpression handles a call_expression node and emits edges.
//
//nolint:gocognit,gocyclo // dispatch resolution requires multiple branches
func (e *Extractor) processCallExpression(
	node *tree_sitter.Node,
	src []byte,
	file, mod, currentFunc string,
	edges *[]treesitter.Edge,
) {
	from := treesitter.SymbolID(currentFunc)
	if currentFunc == "" {
		from = treesitter.SymbolID(mod)
	}

	line := rowToLine(node.StartPosition().Row)

	// Determine what kind of call this is by examining the first child
	firstChild := node.Child(0)
	if firstChild == nil {
		return
	}

	switch firstChild.Kind() {
	case "identifier":
		// Direct function call: helper(42)
		callee := nodeText(firstChild, src)
		*edges = append(*edges, treesitter.Edge{
			From:       from,
			To:         treesitter.SymbolID(callee),
			Kind:       treesitter.EdgeDirect,
			Confidence: 1.0,
			File:       file,
			Line:       line,
		})

	case "scoped_identifier":
		// Static method call: Server::new(8080)
		// Normalize :: to .
		callee := strings.ReplaceAll(nodeText(firstChild, src), "::", ".")
		*edges = append(*edges, treesitter.Edge{
			From:       from,
			To:         treesitter.SymbolID(callee),
			Kind:       treesitter.EdgeDirect,
			Confidence: 1.0,
			File:       file,
			Line:       line,
		})

	case "field_expression":
		// Method call: obj.method()
		e.processFieldCall(firstChild, src, file, currentFunc, from, line, edges)
	}
}

// processFieldCall handles a method call through a field_expression (obj.method()).
//
//nolint:gocognit,gocyclo // dispatch resolution requires multiple branches for trait lookup
func (e *Extractor) processFieldCall(
	fieldExpr *tree_sitter.Node,
	src []byte,
	file, currentFunc string,
	from treesitter.SymbolID,
	line int,
	edges *[]treesitter.Edge,
) {
	// field_expression: identifier "." field_identifier
	var objectName, methodName string
	for i := uint(0); i < fieldExpr.ChildCount(); i++ {
		child := fieldExpr.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "identifier":
			objectName = nodeText(child, src)
		case "field_identifier":
			methodName = nodeText(child, src)
		}
	}

	if methodName == "" {
		return
	}

	// Check if objectName is a parameter with a trait type (for dispatch)
	if objectName != "" && currentFunc != "" {
		key := paramKey{function: currentFunc, param: objectName}
		if paramType, ok := e.paramTypes[key]; ok {
			// Check if paramType is a known trait
			if implementors, ok := e.traitImpls[paramType]; ok && len(implementors) > 0 {
				mod := ""
				// Derive module from currentFunc
				parts := strings.Split(currentFunc, ".")
				if len(parts) > 0 {
					mod = parts[0]
				}
				for _, impl := range implementors {
					to := treesitter.SymbolID(qualifyName(mod, impl, methodName))
					*edges = append(*edges, treesitter.Edge{
						From:       from,
						To:         to,
						Kind:       treesitter.EdgeDispatch,
						Confidence: 0.5,
						File:       file,
						Line:       line,
					})
				}
				return
			}
		}
	}

	// Regular method call
	callee := objectName + "." + methodName
	*edges = append(*edges, treesitter.Edge{
		From:       from,
		To:         treesitter.SymbolID(callee),
		Kind:       treesitter.EdgeDirect,
		Confidence: 0.8,
		File:       file,
		Line:       line,
	})
}

// extractImplTypeName extracts the implementing type name from an impl_item node.
// For `impl Server { ... }` returns "Server".
// For `impl Handler for Server { ... }` returns "Server".
//
//nolint:gocognit // handles both inherent and trait impl header parsing
func extractImplTypeName(node *tree_sitter.Node, src []byte) string {
	hasFOR := false
	var firstName string

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "type_identifier":
			name := nodeText(child, src)
			if hasFOR {
				return name
			}
			if firstName == "" {
				firstName = name
			}
		case "generic_type", "scoped_type_identifier":
			name := extractSimpleTypeName(child, src)
			if hasFOR {
				return name
			}
			if firstName == "" {
				firstName = name
			}
		case "for":
			hasFOR = true
		}
	}

	return firstName
}
