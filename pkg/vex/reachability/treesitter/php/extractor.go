// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package php implements tree-sitter AST extraction for PHP source files.
// It extracts symbols (classes, methods), imports (use declarations),
// and call edges (member calls, static calls, object creation).
package php

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// Compile-time interface conformance check.
// If the Extractor methods diverge from the LanguageExtractor interface,
// this line will produce a compile error pointing directly at the mismatch.
var _ treesitter.LanguageExtractor = (*Extractor)(nil)

// Extractor extracts symbols, imports, and call edges from PHP ASTs.
type Extractor struct {
	// attributes maps SymbolID → attribute names found on the definition.
	// E.g. "#[Route('/path')]" → "@Route"
	attributes map[treesitter.SymbolID][]string

	// publicMethods tracks SymbolIDs for methods declared with "public" visibility.
	publicMethods map[treesitter.SymbolID]bool

	// classOf maps method SymbolID → class name (not fully qualified).
	// Used for controller class detection.
	classOf map[treesitter.SymbolID]string
}

// New creates a new PHP Extractor.
func New() *Extractor {
	return &Extractor{
		attributes:    make(map[treesitter.SymbolID][]string),
		publicMethods: make(map[treesitter.SymbolID]bool),
		classOf:       make(map[treesitter.SymbolID]string),
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

// namespaceFromAST extracts the PHP namespace declaration from the root program node.
// PHP: namespace App\Controllers;
func namespaceFromAST(root *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "namespace_definition" {
			nameNode := child.ChildByFieldName("name")
			if nameNode != nil {
				return nodeText(nameNode, src)
			}
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractSymbols
// ─────────────────────────────────────────────────────────────────────────────

// ExtractSymbols walks the AST to find all class and method definitions.
// It populates the attributes and publicMethods maps for entry point detection.
func (e *Extractor) ExtractSymbols(file string, src []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	// Reset per-call state
	e.attributes = make(map[treesitter.SymbolID][]string)
	e.publicMethods = make(map[treesitter.SymbolID]bool)
	e.classOf = make(map[treesitter.SymbolID]string)

	root := tree.RootNode()
	ns := namespaceFromAST(root, src)

	var symbols []*treesitter.Symbol
	walkProgram(root, src, file, ns, &symbols, e.attributes, e.publicMethods, e.classOf)
	return symbols, nil
}

// walkProgram walks the PHP program root node.
func walkProgram(
	root *tree_sitter.Node,
	src []byte,
	file, ns string,
	symbols *[]*treesitter.Symbol,
	attributes map[treesitter.SymbolID][]string,
	publicMethods map[treesitter.SymbolID]bool,
	classOf map[treesitter.SymbolID]string,
) {
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "class_declaration":
			extractClassNode(child, src, file, ns, symbols, attributes, publicMethods, classOf)
		case "function_definition":
			extractTopLevelFunction(child, src, file, ns, symbols)
		}
	}
}

// extractTopLevelFunction processes a top-level function_definition node.
// PHP global functions are extracted as SymbolFunction kind symbols.
// The symbol ID is "namespace\functionName" if a namespace is present, or just "functionName".
func extractTopLevelFunction(
	node *tree_sitter.Node,
	src []byte,
	file, ns string,
	symbols *[]*treesitter.Symbol,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	funcName := nodeText(nameNode, src)

	var qualifiedName string
	if ns != "" {
		qualifiedName = ns + `\` + funcName
	} else {
		qualifiedName = funcName
	}
	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          funcName,
		QualifiedName: qualifiedName,
		Language:      "php",
		File:          file,
		Package:       ns,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolFunction,
		IsPublic:      true, // PHP top-level functions are always public
	}
	*symbols = append(*symbols, sym)
}

// extractClassNode processes a class_declaration node.
//
//nolint:gocognit // class body traversal handles methods
func extractClassNode(
	node *tree_sitter.Node,
	src []byte,
	file, ns string,
	symbols *[]*treesitter.Symbol,
	attributes map[treesitter.SymbolID][]string,
	publicMethods map[treesitter.SymbolID]bool,
	classOf map[treesitter.SymbolID]string,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	className := nodeText(nameNode, src)

	qualifiedName := qualifyClass(ns, className)
	id := treesitter.SymbolID(qualifiedName)

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          className,
		QualifiedName: qualifiedName,
		Language:      "php",
		File:          file,
		Package:       ns,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
		IsPublic:      true, // PHP classes are always public by default
	}
	*symbols = append(*symbols, sym)

	// Recurse into class body (declaration_list)
	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	for i := uint(0); i < body.ChildCount(); i++ {
		child := body.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "method_declaration" {
			extractMethodNode(child, src, file, ns, className, symbols, attributes, publicMethods, classOf)
		}
	}
}

// extractMethodNode processes a method_declaration node.
func extractMethodNode(
	node *tree_sitter.Node,
	src []byte,
	file, ns, className string,
	symbols *[]*treesitter.Symbol,
	attributes map[treesitter.SymbolID][]string,
	publicMethods map[treesitter.SymbolID]bool,
	classOf map[treesitter.SymbolID]string,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	methodName := nodeText(nameNode, src)

	qualifiedName := qualifyMethod(ns, className, methodName)
	id := treesitter.SymbolID(qualifiedName)

	// Collect method-level attributes
	var attrs []string
	collectAttributes(node, src, &attrs)
	if len(attrs) > 0 {
		attributes[id] = attrs
	}

	// Track visibility for controller entry point detection
	isPublic := hasPublicModifier(node, src)
	if isPublic {
		publicMethods[id] = true
	}

	// Track which class this method belongs to
	classOf[id] = className

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          methodName,
		QualifiedName: qualifiedName,
		Language:      "php",
		File:          file,
		Package:       ns,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolMethod,
		IsPublic:      isPublic,
	}
	*symbols = append(*symbols, sym)
}

// collectAttributes scans an AST node's children for attribute_list nodes.
// In PHP's grammar, #[Route(...)] appears as attribute_list → attribute_group → attribute.
//
//nolint:gocognit,gocyclo // three-level attribute scan requires nested branching
func collectAttributes(node *tree_sitter.Node, src []byte, attrs *[]string) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() != "attribute_list" {
			continue
		}
		// attribute_list: "#[" attribute_group+ "]"
		// attribute_group contains attribute nodes
		for j := uint(0); j < child.ChildCount(); j++ {
			groupOrAttr := child.Child(j)
			if groupOrAttr == nil {
				continue
			}
			if groupOrAttr.Kind() == "attribute_group" {
				for k := uint(0); k < groupOrAttr.ChildCount(); k++ {
					attrNode := groupOrAttr.Child(k)
					if attrNode != nil && attrNode.Kind() == "attribute" {
						attrName := attributeName(attrNode, src)
						if attrName != "" {
							*attrs = append(*attrs, "@"+attrName)
						}
					}
				}
			} else if groupOrAttr.Kind() == "attribute" {
				attrName := attributeName(groupOrAttr, src)
				if attrName != "" {
					*attrs = append(*attrs, "@"+attrName)
				}
			}
		}
	}
}

// attributeName returns the name of an attribute node.
func attributeName(node *tree_sitter.Node, src []byte) string {
	// attribute: name arguments?
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "name" {
			return nodeText(child, src)
		}
	}
	return ""
}

// hasPublicModifier returns true if the node has a "public" visibility_modifier child.
func hasPublicModifier(node *tree_sitter.Node, src []byte) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "visibility_modifier" {
			text := nodeText(child, src)
			if text == "public" {
				return true
			}
		}
	}
	return false
}

// qualifyClass builds a qualified class name using PHP's namespace separator.
// "App" + "UserController" → "App\UserController"
func qualifyClass(ns, className string) string {
	if ns == "" {
		return className
	}
	return ns + `\` + className
}

// qualifyMethod builds a qualified method name: "Namespace\ClassName::methodName".
func qualifyMethod(ns, className, methodName string) string {
	class := qualifyClass(ns, className)
	if class == "" {
		return methodName
	}
	return class + "::" + methodName
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveImports
// ─────────────────────────────────────────────────────────────────────────────

// ResolveImports walks the AST to find all use declarations.
// PHP use declarations: "use GuzzleHttp\Client;", "use GuzzleHttp\Exception\RequestException;"
func (e *Extractor) ResolveImports(file string, src []byte, tree *tree_sitter.Tree, _ string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import
	collectImports(root, src, file, &imports)
	return imports, nil
}

// collectImports recursively finds namespace_use_declaration nodes.
func collectImports(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	if node == nil {
		return
	}

	if node.Kind() == "namespace_use_declaration" {
		extractUseDeclaration(node, src, file, imports)
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectImports(child, src, file, imports)
	}
}

// extractUseDeclaration processes a single namespace_use_declaration node.
// use GuzzleHttp\Client; → Module="GuzzleHttp\Client", Alias="Client"
// use GuzzleHttp\Client as GuzzleClient; → Module="GuzzleHttp\Client", Alias="GuzzleClient"
//
//nolint:gocognit,gocyclo // handles qualified names, aliases, and grouped use declarations
func extractUseDeclaration(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	// namespace_use_declaration: "use" namespace_use_clause+ ";"
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() != "namespace_use_clause" {
			continue
		}

		// namespace_use_clause: qualified_name ("as" name)?
		var fqn, alias string
		for j := uint(0); j < child.ChildCount(); j++ {
			grandchild := child.Child(j)
			if grandchild == nil {
				continue
			}
			switch grandchild.Kind() {
			case "qualified_name":
				fqn = qualifiedNameText(grandchild, src)
			case "name":
				// Could be the alias after "as", or part of qualified_name
				// If we already have fqn set, this is an alias
				if fqn != "" {
					alias = nodeText(grandchild, src)
				}
			}
		}

		if fqn == "" {
			continue
		}

		// Default alias = last segment of qualified name
		if alias == "" {
			parts := strings.Split(fqn, `\`)
			alias = parts[len(parts)-1]
		}

		*imports = append(*imports, treesitter.Import{
			Module: fqn,
			Alias:  alias,
			File:   file,
			Line:   rowToLine(node.StartPosition().Row),
		})
	}
}

// qualifiedNameText reconstructs a PHP qualified name from its AST representation.
// PHP qualified names are: namespace_name "\" name
// e.g. GuzzleHttp\Client or GuzzleHttp\Exception\RequestException
func qualifiedNameText(node *tree_sitter.Node, src []byte) string {
	// The node text already contains backslashes in the source
	return nodeText(node, src)
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractCalls
// ─────────────────────────────────────────────────────────────────────────────

// ExtractCalls walks the AST to find all method invocations and object creations.
func (e *Extractor) ExtractCalls(file string, src []byte, tree *tree_sitter.Tree, _ *treesitter.Scope) ([]treesitter.Edge, error) {
	root := tree.RootNode()
	ns := namespaceFromAST(root, src)

	var edges []treesitter.Edge
	collectCalls(root, src, file, ns, "", "", &edges)
	return edges, nil
}

// callState holds walking context for call extraction.
type callState struct {
	file          string
	ns            string
	currentClass  string
	currentMethod string
	edges         *[]treesitter.Edge
}

// collectCalls recursively visits nodes to find method invocations.
//
//nolint:gocognit,gocyclo // AST walker handles class body, method body, and invocation nodes
func collectCalls(
	node *tree_sitter.Node,
	src []byte,
	file, ns, currentClass, currentMethod string,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	kind := node.Kind()

	switch kind {
	case "class_declaration":
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		className := nodeText(nameNode, src)
		body := node.ChildByFieldName("body")
		if body != nil {
			for i := uint(0); i < body.ChildCount(); i++ {
				collectCalls(body.Child(i), src, file, ns, className, currentMethod, edges)
			}
		}
		return

	case "function_definition":
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		funcName := nodeText(nameNode, src)
		body := node.ChildByFieldName("body")
		if body != nil {
			collectCalls(body, src, file, ns, "", funcName, edges)
		}
		return

	case "method_declaration":
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		methodName := nodeText(nameNode, src)
		body := node.ChildByFieldName("body")
		if body != nil {
			collectCalls(body, src, file, ns, currentClass, methodName, edges)
		}
		return

	case "member_call_expression":
		ctx := &callState{
			file:          file,
			ns:            ns,
			currentClass:  currentClass,
			currentMethod: currentMethod,
			edges:         edges,
		}
		processMemberCall(node, src, ctx)
		// Recurse into arguments for nested calls
		if argsNode := node.ChildByFieldName("arguments"); argsNode != nil {
			for i := uint(0); i < argsNode.ChildCount(); i++ {
				collectCalls(argsNode.Child(i), src, file, ns, currentClass, currentMethod, edges)
			}
		}
		return

	case "scoped_call_expression":
		ctx := &callState{
			file:          file,
			ns:            ns,
			currentClass:  currentClass,
			currentMethod: currentMethod,
			edges:         edges,
		}
		processScopedCall(node, src, ctx)
		// Recurse into arguments
		if argsNode := node.ChildByFieldName("arguments"); argsNode != nil {
			for i := uint(0); i < argsNode.ChildCount(); i++ {
				collectCalls(argsNode.Child(i), src, file, ns, currentClass, currentMethod, edges)
			}
		}
		return

	case "object_creation_expression":
		ctx := &callState{
			file:          file,
			ns:            ns,
			currentClass:  currentClass,
			currentMethod: currentMethod,
			edges:         edges,
		}
		processObjectCreation(node, src, ctx)
		// Recurse into arguments
		if argsNode := node.ChildByFieldName("arguments"); argsNode != nil {
			for i := uint(0); i < argsNode.ChildCount(); i++ {
				collectCalls(argsNode.Child(i), src, file, ns, currentClass, currentMethod, edges)
			}
		}
		return

	case "function_call_expression":
		ctx := &callState{
			file:          file,
			ns:            ns,
			currentClass:  currentClass,
			currentMethod: currentMethod,
			edges:         edges,
		}
		processFunctionCall(node, src, ctx)
		if argsNode := node.ChildByFieldName("arguments"); argsNode != nil {
			for i := uint(0); i < argsNode.ChildCount(); i++ {
				collectCalls(argsNode.Child(i), src, file, ns, currentClass, currentMethod, edges)
			}
		}
		return
	}

	// Recurse into all children
	for i := uint(0); i < node.ChildCount(); i++ {
		collectCalls(node.Child(i), src, file, ns, currentClass, currentMethod, edges)
	}
}

// processMemberCall handles a member_call_expression: $obj->method($args)
// PHP grammar: member_call_expression = object "->" name arguments
func processMemberCall(node *tree_sitter.Node, src []byte, ctx *callState) {
	// The object is the first child, name is the "name" field
	var objectText, methodName string

	// First child = the object (variable, member access, etc.)
	if objNode := node.Child(0); objNode != nil {
		objectText = nodeText(objNode, src)
		// Strip the "$" prefix for variable names
		objectText = strings.TrimPrefix(objectText, "$")
	}

	if nameNode := node.ChildByFieldName("name"); nameNode != nil {
		methodName = nodeText(nameNode, src)
	}

	if objectText == "" || methodName == "" {
		return
	}

	from := ctx.buildFrom()
	// Emit as "ObjectType::method" — the type resolver will enhance this
	// For now we emit "varName::method" which gets matched against type-inferred targets
	toStr := objectText + "::" + methodName

	*ctx.edges = append(*ctx.edges, treesitter.Edge{
		From:       from,
		To:         treesitter.SymbolID(toStr),
		Kind:       treesitter.EdgeDirect,
		Confidence: 0.8, // lower because we don't know the variable's type statically
		File:       ctx.file,
		Line:       rowToLine(node.StartPosition().Row),
	})
}

// processScopedCall handles a scoped_call_expression: Class::method($args)
// PHP grammar: scoped_call_expression = scope "::" name arguments
func processScopedCall(node *tree_sitter.Node, src []byte, ctx *callState) {
	var scopeName, methodName string

	// scope is the first child (class name or "static"/"self"/"parent")
	if scopeNode := node.Child(0); scopeNode != nil {
		scopeName = nodeText(scopeNode, src)
	}

	if nameNode := node.ChildByFieldName("name"); nameNode != nil {
		methodName = nodeText(nameNode, src)
	}

	if scopeName == "" || methodName == "" {
		return
	}

	from := ctx.buildFrom()
	toStr := scopeName + "::" + methodName

	*ctx.edges = append(*ctx.edges, treesitter.Edge{
		From:       from,
		To:         treesitter.SymbolID(toStr),
		Kind:       treesitter.EdgeDirect,
		Confidence: 1.0,
		File:       ctx.file,
		Line:       rowToLine(node.StartPosition().Row),
	})
}

// processObjectCreation handles an object_creation_expression (new Foo(...)).
// PHP grammar: object_creation_expression = "new" class_name arguments?
func processObjectCreation(node *tree_sitter.Node, src []byte, ctx *callState) {
	// Find the class name — skip the "new" keyword
	var typeName string
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		k := child.Kind()
		if k == "new" {
			continue
		}
		if k == "name" || k == "qualified_name" {
			typeName = nodeText(child, src)
			break
		}
	}

	if typeName == "" {
		return
	}

	from := ctx.buildFrom()
	to := treesitter.SymbolID(typeName + ".<init>")

	*ctx.edges = append(*ctx.edges, treesitter.Edge{
		From:       from,
		To:         to,
		Kind:       treesitter.EdgeDirect,
		Confidence: 1.0,
		File:       ctx.file,
		Line:       rowToLine(node.StartPosition().Row),
	})
}

// processFunctionCall handles a function_call_expression: func($args)
func processFunctionCall(node *tree_sitter.Node, src []byte, ctx *callState) {
	var funcName string

	// First child is the function name (name or qualified_name)
	if funcNode := node.Child(0); funcNode != nil {
		funcName = nodeText(funcNode, src)
	}

	if funcName == "" {
		return
	}

	from := ctx.buildFrom()

	*ctx.edges = append(*ctx.edges, treesitter.Edge{
		From:       from,
		To:         treesitter.SymbolID(funcName),
		Kind:       treesitter.EdgeDirect,
		Confidence: 1.0,
		File:       ctx.file,
		Line:       rowToLine(node.StartPosition().Row),
	})
}

// buildFrom constructs the caller's SymbolID from the current context.
func (ctx *callState) buildFrom() treesitter.SymbolID {
	if ctx.currentClass != "" && ctx.currentMethod != "" {
		return treesitter.SymbolID(qualifyMethod(ctx.ns, ctx.currentClass, ctx.currentMethod))
	}
	if ctx.currentClass != "" {
		return treesitter.SymbolID(qualifyClass(ctx.ns, ctx.currentClass))
	}
	// Top-level function context: currentClass is empty, currentMethod holds the function name.
	if ctx.currentMethod != "" {
		if ctx.ns != "" {
			return treesitter.SymbolID(ctx.ns + `\` + ctx.currentMethod)
		}
		return treesitter.SymbolID(ctx.currentMethod)
	}
	if ctx.ns != "" {
		return treesitter.SymbolID(ctx.ns)
	}
	return treesitter.SymbolID(ctx.file)
}
