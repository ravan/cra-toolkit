// Package csharp implements tree-sitter AST extraction for C# source files.
// It extracts symbols (classes, methods, constructors), imports (using directives),
// and call edges (invocation expressions, object creation).
package csharp

import (
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// Compile-time interface conformance check.
// If the Extractor methods diverge from the LanguageExtractor interface,
// this line will produce a compile error pointing directly at the mismatch.
var _ treesitter.LanguageExtractor = (*Extractor)(nil)

// Extractor extracts symbols, imports, and call edges from C# ASTs.
type Extractor struct {
	// attributes maps SymbolID → attribute names found on the definition.
	// E.g. "[HttpPost]" → "HttpPost"
	attributes map[treesitter.SymbolID][]string

	// staticMethods is the set of SymbolIDs for methods declared with "static" modifier.
	// Used to enforce the C# Main entry point contract: static void Main.
	staticMethods map[treesitter.SymbolID]bool

	// mapHandlers tracks method names or lambda symbols registered via app.MapGet/MapPost etc.
	mapHandlers map[string]bool
}

// New creates a new C# Extractor.
func New() *Extractor {
	return &Extractor{
		attributes:    make(map[treesitter.SymbolID][]string),
		staticMethods: make(map[treesitter.SymbolID]bool),
		mapHandlers:   make(map[string]bool),
	}
}

// ModuleFromFile derives a module/class name hint from a C# file path.
// "DataController.cs" → "DataController", "/path/to/Service.cs" → "Service"
func ModuleFromFile(file string) string {
	base := filepath.Base(file)
	return strings.TrimSuffix(base, filepath.Ext(base))
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

// namespaceFromAST extracts the namespace from the root of a C# AST.
// Supports both block-scoped (namespace Foo { }) and file-scoped (namespace Foo;) declarations.
func namespaceFromAST(root *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		k := child.Kind()
		if k == "namespace_declaration" || k == "file_scoped_namespace_declaration" {
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
// It populates the attributes and staticMethods maps for entry point detection.
func (e *Extractor) ExtractSymbols(file string, src []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	// Reset per-call state
	e.attributes = make(map[treesitter.SymbolID][]string)
	e.staticMethods = make(map[treesitter.SymbolID]bool)
	e.mapHandlers = make(map[string]bool)

	root := tree.RootNode()
	ns := namespaceFromAST(root, src)

	var symbols []*treesitter.Symbol
	// Walk the top-level nodes: for file-scoped namespaces, classes appear at root level
	// For block-scoped namespaces, classes appear inside the declaration_list body
	walkTopLevel(root, src, file, ns, &symbols, e.attributes, e.staticMethods, e.mapHandlers)
	return symbols, nil
}

// walkTopLevel walks the compilation_unit root and dispatches to appropriate handlers.
//
//nolint:gocognit,gocyclo // top-level walker handles multiple namespace forms and class declarations
func walkTopLevel(
	root *tree_sitter.Node,
	src []byte,
	file, ns string,
	symbols *[]*treesitter.Symbol,
	attributes map[treesitter.SymbolID][]string,
	staticMethods map[treesitter.SymbolID]bool,
	mapHandlers map[string]bool,
) {
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		k := child.Kind()
		switch k {
		case "namespace_declaration":
			// Block-scoped namespace: namespace Foo { ... }
			body := child.ChildByFieldName("body")
			if body == nil {
				continue
			}
			nsName := ""
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				nsName = nodeText(nameNode, src)
			}
			walkDeclarationList(body, src, file, nsName, "", symbols, attributes, staticMethods)

		case "file_scoped_namespace_declaration":
			// File-scoped namespace already captured in ns; classes at root level below

		case "class_declaration":
			extractClassNode(child, src, file, ns, "", symbols, attributes, staticMethods)

		case "global_statement":
			// Minimal API / top-level statements: look for app.MapGet etc.
			collectMapHandlers(child, src, mapHandlers)
		}
	}

	// For file-scoped namespaces: classes appear at root level after the namespace declaration
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "class_declaration" {
			extractClassNode(child, src, file, ns, "", symbols, attributes, staticMethods)
		}
	}
}

// walkDeclarationList recurses through a declaration_list (class body or namespace body).
func walkDeclarationList(
	body *tree_sitter.Node,
	src []byte,
	file, ns, currentClass string,
	symbols *[]*treesitter.Symbol,
	attributes map[treesitter.SymbolID][]string,
	staticMethods map[treesitter.SymbolID]bool,
) {
	for i := uint(0); i < body.ChildCount(); i++ {
		child := body.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "class_declaration" {
			extractClassNode(child, src, file, ns, currentClass, symbols, attributes, staticMethods)
		}
	}
}

// extractClassNode processes a class_declaration node.
//
//nolint:gocognit // class body traversal handles methods, constructors, nested classes
func extractClassNode(
	node *tree_sitter.Node,
	src []byte,
	file, ns, outerClass string,
	symbols *[]*treesitter.Symbol,
	attributes map[treesitter.SymbolID][]string,
	staticMethods map[treesitter.SymbolID]bool,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	className := nodeText(nameNode, src)

	qualifiedName := qualifyClass(ns, outerClass, className)
	id := treesitter.SymbolID(qualifiedName)

	// Collect class-level attributes
	var classAttrs []string
	collectAttributes(node, src, &classAttrs)
	if len(classAttrs) > 0 {
		attributes[id] = classAttrs
	}

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          className,
		QualifiedName: qualifiedName,
		Language:      "csharp",
		File:          file,
		Package:       ns,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
	}
	*symbols = append(*symbols, sym)

	// Recurse into class body
	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	for i := uint(0); i < body.ChildCount(); i++ {
		child := body.Child(i)
		if child == nil {
			continue
		}
		childKind := child.Kind()
		switch childKind {
		case "method_declaration", "constructor_declaration":
			extractMethodNode(child, src, file, ns, className, symbols, attributes, staticMethods)
		case "class_declaration":
			// Nested class
			innerOuter := qualifiedClass(outerClass, className)
			extractClassNode(child, src, file, ns, innerOuter, symbols, attributes, staticMethods)
		}
	}
}

// extractMethodNode processes a method_declaration or constructor_declaration.
func extractMethodNode(
	node *tree_sitter.Node,
	src []byte,
	file, ns, className string,
	symbols *[]*treesitter.Symbol,
	attributes map[treesitter.SymbolID][]string,
	staticMethods map[treesitter.SymbolID]bool,
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

	// Track static methods for Main entry point detection
	if hasStaticModifier(node, src) {
		staticMethods[id] = true
	}

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          methodName,
		QualifiedName: qualifiedName,
		Language:      "csharp",
		File:          file,
		Package:       ns,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolMethod,
	}
	*symbols = append(*symbols, sym)
}

// collectAttributes scans an AST node's children for attribute_list/attribute nodes.
// In C#'s grammar, attributes appear as attribute_list children directly on the declaration.
//
//nolint:gocognit // two-level attribute scan requires nested branching
func collectAttributes(node *tree_sitter.Node, src []byte, attrs *[]string) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() != "attribute_list" {
			continue
		}
		// attribute_list: "[" attribute ("," attribute)* "]"
		for j := uint(0); j < child.ChildCount(); j++ {
			grandchild := child.Child(j)
			if grandchild == nil || grandchild.Kind() != "attribute" {
				continue
			}
			attrName := attributeName(grandchild, src)
			if attrName != "" {
				*attrs = append(*attrs, "@"+attrName)
			}
		}
	}
}

// attributeName returns the name of an attribute node.
// attribute: identifier attribute_argument_list?
func attributeName(node *tree_sitter.Node, src []byte) string {
	nameNode := node.ChildByFieldName("name")
	if nameNode != nil {
		return nodeText(nameNode, src)
	}
	// Fallback: first identifier child
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return nodeText(child, src)
		}
	}
	return ""
}

// hasStaticModifier returns true if the node has a "static" modifier child.
func hasStaticModifier(node *tree_sitter.Node, src []byte) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "modifier" {
			for j := uint(0); j < child.ChildCount(); j++ {
				grandchild := child.Child(j)
				if grandchild != nil && nodeText(grandchild, src) == "static" {
					return true
				}
			}
		}
	}
	return false
}

// collectMapHandlers scans a global_statement for app.MapGet/MapPost/etc. calls.
// Records the handler lambda or function reference as a map handler.
func collectMapHandlers(node *tree_sitter.Node, src []byte, mapHandlers map[string]bool) {
	if node == nil {
		return
	}
	if node.Kind() == "invocation_expression" {
		expr := node.Child(0)
		if expr != nil && expr.Kind() == "member_access_expression" {
			memberName := ""
			if mn := expr.ChildByFieldName("name"); mn != nil {
				memberName = nodeText(mn, src)
			}
			if isMapMethod(memberName) {
				mapHandlers[memberName] = true
			}
		}
	}
	for i := uint(0); i < node.ChildCount(); i++ {
		collectMapHandlers(node.Child(i), src, mapHandlers)
	}
}

// isMapMethod returns true if the name is a Minimal API Map* method.
func isMapMethod(name string) bool {
	switch name {
	case "MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch":
		return true
	}
	return false
}

// qualifyClass builds a qualified class name.
func qualifyClass(ns, outerClass, className string) string {
	parts := []string{}
	if ns != "" {
		parts = append(parts, ns)
	}
	if outerClass != "" {
		parts = append(parts, outerClass)
	}
	parts = append(parts, className)
	return strings.Join(parts, ".")
}

// qualifyMethod builds a qualified method name: "Namespace.ClassName.MethodName".
func qualifyMethod(ns, className, methodName string) string {
	parts := []string{}
	if ns != "" {
		parts = append(parts, ns)
	}
	if className != "" {
		parts = append(parts, className)
	}
	parts = append(parts, methodName)
	return strings.Join(parts, ".")
}

// qualifiedClass builds "OuterClass.InnerClass" for nested class tracking.
func qualifiedClass(outerClass, className string) string {
	if outerClass == "" {
		return className
	}
	return outerClass + "." + className
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveImports
// ─────────────────────────────────────────────────────────────────────────────

// ResolveImports walks the AST to find all using directives.
// C# using directives: "using System;", "using Microsoft.AspNetCore.Mvc;"
func (e *Extractor) ResolveImports(file string, src []byte, tree *tree_sitter.Tree, _ string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import
	collectImports(root, src, file, &imports)
	return imports, nil
}

// collectImports recursively finds using_directive nodes.
func collectImports(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	if node == nil {
		return
	}

	if node.Kind() == "using_directive" {
		extractUsingDirective(node, src, file, imports)
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectImports(child, src, file, imports)
	}
}

// extractUsingDirective processes a single using_directive node.
// using_directive: "using" ["static"] (qualified_name | identifier) ";"
//
//nolint:gocognit // handles qualified names and aliases across grammar versions
func extractUsingDirective(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		k := child.Kind()
		if k == "qualified_name" || k == "identifier" {
			fqn := nodeText(child, src)
			if fqn == "" {
				continue
			}
			// Alias = last segment of the qualified name
			alias := fqn
			if idx := strings.LastIndexByte(fqn, '.'); idx >= 0 {
				alias = fqn[idx+1:]
			}
			*imports = append(*imports, treesitter.Import{
				Module: fqn,
				Alias:  alias,
				File:   file,
				Line:   rowToLine(node.StartPosition().Row),
			})
			return
		}
	}
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
	case "namespace_declaration":
		body := node.ChildByFieldName("body")
		if body != nil {
			nsName := ""
			if nameNode := node.ChildByFieldName("name"); nameNode != nil {
				nsName = nodeText(nameNode, src)
			}
			collectCalls(body, src, file, nsName, currentClass, currentMethod, edges)
		}
		return

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

	case "method_declaration", "constructor_declaration":
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

	case "invocation_expression":
		ctx := &callState{
			file:          file,
			ns:            ns,
			currentClass:  currentClass,
			currentMethod: currentMethod,
			edges:         edges,
		}
		processInvocationExpression(node, src, ctx)
		// Recurse into arguments for nested calls
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
	}

	// Recurse into all children
	for i := uint(0); i < node.ChildCount(); i++ {
		collectCalls(node.Child(i), src, file, ns, currentClass, currentMethod, edges)
	}
}

// processInvocationExpression handles an invocation_expression node and emits call edges.
//
// C# grammar: invocation_expression = expression argument_list
// The expression is either:
//   - member_access_expression: "JsonConvert.DeserializeObject" → object="JsonConvert", name="DeserializeObject"
//   - identifier: "Ok" (unqualified call within same class or global method)
//
//nolint:gocognit,gocyclo // multiple call expression forms require branching
func processInvocationExpression(node *tree_sitter.Node, src []byte, ctx *callState) {
	if node.ChildCount() == 0 {
		return
	}

	// First child is the callable expression
	expr := node.Child(0)
	if expr == nil {
		return
	}

	from := ctx.buildFrom()

	var toStr string
	switch expr.Kind() {
	case "member_access_expression":
		// object.method(args)
		// First child = object expression, name field = method name
		objectText := ""
		if objNode := expr.Child(0); objNode != nil {
			objectText = nodeText(objNode, src)
		}
		methodName := ""
		if mn := expr.ChildByFieldName("name"); mn != nil {
			methodName = nodeText(mn, src)
		}
		if objectText != "" && methodName != "" {
			toStr = objectText + "." + methodName
		} else if methodName != "" {
			toStr = methodName
		}

	case "identifier":
		// Unqualified call
		name := nodeText(expr, src)
		if ctx.currentClass != "" {
			toStr = qualifyMethod(ctx.ns, ctx.currentClass, name)
		} else {
			toStr = name
		}
	}

	if toStr == "" {
		return
	}

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
// C# grammar: object_creation_expression = "new" type argument_list? object_creation_type_initializer?
func processObjectCreation(node *tree_sitter.Node, src []byte, ctx *callState) {
	// Find the type node — it's the first non-"new" child
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
		if k == "identifier" || k == "qualified_name" || k == "generic_name" {
			typeName = simpleTypeName(nodeText(child, src))
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

// buildFrom constructs the caller's SymbolID from the current context.
func (ctx *callState) buildFrom() treesitter.SymbolID {
	if ctx.currentClass != "" && ctx.currentMethod != "" {
		return treesitter.SymbolID(qualifyMethod(ctx.ns, ctx.currentClass, ctx.currentMethod))
	}
	if ctx.currentClass != "" {
		return treesitter.SymbolID(qualifyClass(ctx.ns, "", ctx.currentClass))
	}
	return treesitter.SymbolID(ctx.ns)
}

// simpleTypeName strips generic parameters from a type name.
// "List<string>" → "List", "Dictionary<string,int>" → "Dictionary"
func simpleTypeName(name string) string {
	if idx := strings.IndexByte(name, '<'); idx > 0 {
		name = name[:idx]
	}
	// For qualified names, keep as-is (will be used in edge target)
	return strings.TrimSpace(name)
}
