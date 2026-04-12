// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

// Package ruby implements tree-sitter AST extraction for Ruby source files.
// It extracts symbols (classes, modules, methods), imports (require/require_relative),
// and call edges (method calls, scope resolution calls, metaprogramming dispatch).
package ruby

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
)

// Compile-time interface conformance check.
// If the Extractor methods diverge from the LanguageExtractor interface,
// this line will produce a compile error pointing directly at the mismatch.
var _ treesitter.LanguageExtractor = (*Extractor)(nil)

// routeAction holds a route-to-action mapping parsed from routes.rb.
// E.g. "pages#parse" → controller="PagesController", action="parse"
type routeAction struct {
	controller string // e.g. "PagesController"
	action     string // e.g. "parse"
}

// MixinEntry records a single include/extend/prepend statement.
type MixinEntry struct {
	Module string
	Kind   string // "include", "extend", "prepend"
}

// CrossFileState accumulates cross-file Ruby metadata collected during extraction.
type CrossFileState struct {
	Mixins        map[string][]MixinEntry // class/module name → mixins applied
	Hierarchy     map[string]string       // class name → superclass name
	ModuleMethods map[string][]string     // module name → method names
}

func newCrossFileState() *CrossFileState {
	return &CrossFileState{
		Mixins:        make(map[string][]MixinEntry),
		Hierarchy:     make(map[string]string),
		ModuleMethods: make(map[string][]string),
	}
}

// Extractor extracts symbols, imports, and call edges from Ruby ASTs.
type Extractor struct {
	// routes holds parsed controller#action pairs from routes.rb
	routes []routeAction
	// state accumulates cross-file mixin/hierarchy/module-method data
	state *CrossFileState
}

// New creates a new Ruby Extractor.
func New() *Extractor {
	return &Extractor{state: newCrossFileState()}
}

// State returns the cross-file state accumulated by this extractor.
func (e *Extractor) State() *CrossFileState {
	return e.state
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

// ─────────────────────────────────────────────────────────────────────────────
// ExtractSymbols
// ─────────────────────────────────────────────────────────────────────────────

// visibility represents Ruby method visibility level.
type visibility int

const (
	visPublic    visibility = iota
	visProtected            // protected methods are not publicly accessible
	visPrivate              // private methods are not publicly accessible
)

// isVisibilityKeyword returns true if the given name is a Ruby visibility modifier.
func isVisibilityKeyword(name string) bool {
	return name == "private" || name == "protected" || name == "public"
}

// parseVisibility converts a visibility keyword string to a visibility constant.
func parseVisibility(name string) visibility {
	switch name {
	case "protected":
		return visProtected
	case "private":
		return visPrivate
	default:
		return visPublic
	}
}

// ExtractSymbols walks the AST to find all class/module/method definitions,
// Rake tasks, and Sinatra route blocks.
func (e *Extractor) ExtractSymbols(file string, src []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	root := tree.RootNode()
	var symbols []*treesitter.Symbol
	walkProgram(root, src, file, nil, &symbols, e.state)
	return symbols, nil
}

// walkProgram walks the Ruby program root node.
//
//nolint:gocognit // top-level dispatch for class, module, rake, sinatra
func walkProgram(
	root *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
	state *CrossFileState,
) {
	if root == nil {
		return
	}
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "class":
			extractClassNode(child, src, file, scopeStack, symbols, state)
		case "module":
			extractModuleNode(child, src, file, scopeStack, symbols, state)
		case "call":
			extractTopLevelCall(child, src, file, symbols)
		}
	}
}

// extractClassNode processes a class node.
func extractClassNode(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
	state *CrossFileState,
) {
	// Ruby AST: class → constant (name), superclass?, body_statement
	// The first constant child is the class name
	extractContainerNode(node, src, file, treesitter.SymbolClass, scopeStack, symbols, state)
}

// extractModuleNode processes a module node.
func extractModuleNode(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
	state *CrossFileState,
) {
	extractContainerNode(node, src, file, treesitter.SymbolModule, scopeStack, symbols, state)
}

// extractContainerNode handles shared extraction logic for class and module nodes.
func extractContainerNode(
	node *tree_sitter.Node,
	src []byte,
	file string,
	kind treesitter.SymbolKind,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
	state *CrossFileState,
) {
	name := classOrModuleName(node, src)
	if name == "" {
		return
	}

	var nameParts []string
	if strings.Contains(name, "::") {
		nameParts = strings.Split(name, "::")
	} else {
		nameParts = []string{name}
	}
	newStack := append(append([]string{}, scopeStack...), nameParts...)
	qualifiedName := strings.Join(newStack, "::")

	sym := &treesitter.Symbol{
		ID:            treesitter.SymbolID(qualifiedName),
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "ruby",
		File:          file,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          kind,
		IsPublic:      true, // classes and modules are always public in normal Ruby usage
	}
	*symbols = append(*symbols, sym)

	// Record superclass hierarchy for class nodes.
	// The Ruby AST superclass node has kind "superclass" with children: "<" and constant/scope_resolution.
	if kind == treesitter.SymbolClass {
		if superclassNode := node.ChildByFieldName("superclass"); superclassNode != nil {
			superclassName := extractSuperclassName(superclassNode, src)
			if superclassName != "" {
				state.Hierarchy[qualifiedName] = superclassName
			}
		}
	}

	// Walk body for methods
	body := node.ChildByFieldName("body")
	if body != nil {
		extractMethodsFromBody(body, src, file, newStack, symbols, state, kind)
	}
}

// classOrModuleName extracts the name from a class or module node.
// It handles both simple names (constant) and compound names (scope_resolution like Admin::UsersController).
func classOrModuleName(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "constant":
			return nodeText(child, src)
		case "scope_resolution":
			return nodeText(child, src)
		}
	}
	return ""
}

// extractSuperclassName extracts the superclass name from a "superclass" AST node.
// The superclass node has the form: "<" constant/scope_resolution
func extractSuperclassName(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "constant", "scope_resolution":
			return extractConstantName(child, src)
		}
	}
	return ""
}

// isMixinKeyword returns true if the name is a Ruby mixin keyword.
func isMixinKeyword(name string) bool {
	return name == "include" || name == "extend" || name == "prepend"
}

// extractConstantName extracts a fully-qualified constant name from a constant or scope_resolution node.
func extractConstantName(node *tree_sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	switch node.Kind() {
	case "constant":
		return nodeText(node, src)
	case "scope_resolution":
		var parts []string
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			switch child.Kind() {
			case "constant":
				parts = append(parts, nodeText(child, src))
			case "scope_resolution":
				parts = append(parts, extractConstantName(child, src))
			}
		}
		return strings.Join(parts, "::")
	}
	return nodeText(node, src)
}

// extractMethodsFromBody walks a body_statement to find method and singleton_method nodes.
// It tracks Ruby visibility modifiers (private/protected/public) and applies them to methods.
// It also records mixin declarations and (for modules) collects method names into state.
//
//nolint:gocognit,gocyclo // visibility state machine requires multiple case branches
func extractMethodsFromBody(
	body *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	symbols *[]*treesitter.Symbol,
	state *CrossFileState,
	containerKind treesitter.SymbolKind,
) {
	if body == nil {
		return
	}

	qualifiedName := strings.Join(scopeStack, "::")

	// privateOverrides collects method names explicitly privatised via `private :name` syntax.
	privateOverrides := make(map[string]bool)

	// vis tracks the current visibility state as we scan the body in order.
	vis := visPublic

	// firstPassSymbols collects symbols during the first pass (before override application).
	var firstPassSymbols []*treesitter.Symbol

	for i := uint(0); i < body.ChildCount(); i++ {
		child := body.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "method":
			extractMethodNode(child, src, file, scopeStack, vis, &firstPassSymbols)
		case "singleton_method":
			extractSingletonMethodNode(child, src, file, scopeStack, vis, &firstPassSymbols)
		case "class":
			extractClassNode(child, src, file, scopeStack, &firstPassSymbols, state)
		case "module":
			extractModuleNode(child, src, file, scopeStack, &firstPassSymbols, state)
		case "identifier":
			// Bare visibility keyword, e.g. `private` or `protected` on its own line.
			name := nodeText(child, src)
			if isVisibilityKeyword(name) {
				vis = parseVisibility(name)
			}
		case "call":
			// Could be `private :method_name` or `private :a, :b` with symbol arguments,
			// attr_accessor/attr_reader/attr_writer declarations,
			// or include/extend/prepend mixin declarations.
			firstChildText := ""
			if child.ChildCount() > 0 {
				if fc := child.Child(0); fc != nil {
					firstChildText = nodeText(fc, src)
				}
			}
			vis = processBodyCall(child, src, file, scopeStack, qualifiedName, firstChildText, vis, &firstPassSymbols, privateOverrides, state)
		}
	}

	// Second pass: apply privateOverrides to method symbols only.
	// Classes and modules are always IsPublic=true; skip them to preserve that invariant.
	for _, sym := range firstPassSymbols {
		if sym.Kind != treesitter.SymbolMethod {
			*symbols = append(*symbols, sym)
			continue
		}
		if override, ok := privateOverrides[sym.Name]; ok {
			sym.IsPublic = !override
		}
		*symbols = append(*symbols, sym)
	}

	// For module containers, record method names in state.ModuleMethods.
	if containerKind == treesitter.SymbolModule {
		for _, sym := range firstPassSymbols {
			if sym.Kind == treesitter.SymbolMethod {
				state.ModuleMethods[qualifiedName] = append(state.ModuleMethods[qualifiedName], sym.Name)
			}
		}
	}
}

// processBodyCall handles a `call` node found in a class/module body.
// It dispatches to attr synthesis, mixin recording, or visibility tracking.
// It returns the (possibly updated) current visibility.
func processBodyCall(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	qualifiedName string,
	firstChildText string,
	vis visibility,
	symbols *[]*treesitter.Symbol,
	privateOverrides map[string]bool,
	state *CrossFileState,
) visibility {
	switch {
	case isAttrDeclaration(firstChildText):
		extractAttrMethods(node, src, file, scopeStack, vis, symbols)
	case isMixinKeyword(firstChildText):
		extractMixins(node, src, firstChildText, qualifiedName, state)
	case isVisibilityKeyword(firstChildText):
		return applyVisibilityCall(node, src, firstChildText, vis, privateOverrides)
	}
	return vis
}

// applyVisibilityCall applies a visibility modifier call (e.g. private, protected, public).
// It returns the updated visibility after the call.
func applyVisibilityCall(
	node *tree_sitter.Node,
	src []byte,
	keyword string,
	vis visibility,
	privateOverrides map[string]bool,
) visibility {
	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		// No arguments: bare visibility toggle.
		return parseVisibility(keyword)
	}
	// Has arguments: explicit per-method override, e.g. `private :beta`.
	for j := uint(0); j < argList.ChildCount(); j++ {
		arg := argList.Child(j)
		if arg == nil {
			continue
		}
		if arg.Kind() == "simple_symbol" {
			methodName := strings.TrimPrefix(nodeText(arg, src), ":")
			if methodName != "" {
				switch keyword {
				case "private", "protected":
					privateOverrides[methodName] = true
				case "public":
					privateOverrides[methodName] = false
				}
			}
		}
	}
	return vis
}

// extractMixins processes an include/extend/prepend call and records mixins in state.
func extractMixins(
	node *tree_sitter.Node,
	src []byte,
	kind string,
	qualifiedName string,
	state *CrossFileState,
) {
	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return
	}
	for j := uint(0); j < argList.ChildCount(); j++ {
		arg := argList.Child(j)
		if arg == nil {
			continue
		}
		moduleName := extractConstantName(arg, src)
		if moduleName != "" {
			state.Mixins[qualifiedName] = append(state.Mixins[qualifiedName], MixinEntry{
				Module: moduleName,
				Kind:   kind,
			})
		}
	}
}

// extractMethodNode processes a `method` node (def foo).
// Ruby AST: method → "def", identifier (name), body_statement, "end"
func extractMethodNode(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	vis visibility,
	symbols *[]*treesitter.Symbol,
) {
	appendMethodSymbol(file, scopeStack, methodNameFromNode(node, src), node, vis, symbols)
}

// extractSingletonMethodNode processes a `singleton_method` node (def self.foo).
// Ruby AST: singleton_method → "def", "self", ".", identifier (name), body_statement, "end"
func extractSingletonMethodNode(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	vis visibility,
	symbols *[]*treesitter.Symbol,
) {
	appendMethodSymbol(file, scopeStack, singletonMethodName(node, src), node, vis, symbols)
}

// appendMethodSymbol creates a method symbol and appends it to the symbol list.
func appendMethodSymbol(
	file string,
	scopeStack []string,
	methodName string,
	node *tree_sitter.Node,
	vis visibility,
	symbols *[]*treesitter.Symbol,
) {
	if methodName == "" {
		return
	}

	className := strings.Join(scopeStack, "::")
	qualifiedName := className + "::" + methodName

	sym := &treesitter.Symbol{
		ID:            treesitter.SymbolID(qualifiedName),
		Name:          methodName,
		QualifiedName: qualifiedName,
		Language:      "ruby",
		File:          file,
		Package:       className,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolMethod,
		IsPublic:      vis == visPublic,
	}
	*symbols = append(*symbols, sym)
}

// isAttrDeclaration returns true if name is an attr_* macro.
func isAttrDeclaration(name string) bool {
	return name == "attr_accessor" || name == "attr_reader" || name == "attr_writer"
}

// extractAttrMethods synthesizes getter and/or setter method symbols for attr_* declarations.
// - attr_reader :name  → getter  ClassName::name
// - attr_writer :name  → setter  ClassName::name=
// - attr_accessor :name → both
func extractAttrMethods(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	vis visibility,
	symbols *[]*treesitter.Symbol,
) {
	if node.ChildCount() == 0 {
		return
	}
	methodText := nodeText(node.Child(0), src)
	args := node.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	className := strings.Join(scopeStack, "::")
	for i := uint(0); i < args.ChildCount(); i++ {
		child := args.Child(i)
		if child == nil || child.Kind() != "simple_symbol" {
			continue
		}
		attrName := strings.TrimPrefix(nodeText(child, src), ":")
		if attrName == "" {
			continue
		}

		makeMethod := func(name string) {
			qualifiedName := className + "::" + name
			*symbols = append(*symbols, &treesitter.Symbol{
				ID:            treesitter.SymbolID(qualifiedName),
				Name:          name,
				QualifiedName: qualifiedName,
				Language:      "ruby",
				File:          file,
				Package:       className,
				StartLine:     rowToLine(node.StartPosition().Row),
				EndLine:       rowToLine(node.EndPosition().Row),
				Kind:          treesitter.SymbolMethod,
				IsPublic:      vis == visPublic,
			})
		}

		switch methodText {
		case "attr_reader":
			makeMethod(attrName)
		case "attr_writer":
			makeMethod(attrName + "=")
		case "attr_accessor":
			makeMethod(attrName)
			makeMethod(attrName + "=")
		}
	}
}

// methodNameFromNode returns the method name from a `method` node.
// In Ruby AST, the identifier after "def" is the second child.
func methodNameFromNode(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "identifier" {
			return nodeText(child, src)
		}
	}
	return ""
}

// singletonMethodName returns the method name from a `singleton_method` node.
// Ruby AST: singleton_method → def, self/object, ".", identifier, body
// We look for the last identifier before the body_statement.
func singletonMethodName(node *tree_sitter.Node, src []byte) string {
	// Walk forward; the method name identifier comes after the "." separator
	sawDot := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "." {
			sawDot = true
			continue
		}
		if sawDot && child.Kind() == "identifier" {
			return nodeText(child, src)
		}
	}
	return ""
}

// extractTopLevelCall handles top-level `call` nodes to detect:
// - Rake tasks: task :name do...end
// - Sinatra routes: get '/path' do...end, post '/path' do...end, etc.
//
//nolint:gocognit // dispatches to rake vs sinatra detection
func extractTopLevelCall(
	node *tree_sitter.Node,
	src []byte,
	file string,
	symbols *[]*treesitter.Symbol,
) {
	// The first child of a call node is the method identifier
	if node.ChildCount() == 0 {
		return
	}
	firstChild := node.Child(0)
	if firstChild == nil {
		return
	}
	methodName := nodeText(firstChild, src)

	switch methodName {
	case "task":
		extractRakeTask(node, src, file, symbols)
	case "get", "post", "put", "delete", "patch", "options", "head":
		// Could be Sinatra route or Rails route helper
		extractSinatraRoute(node, src, file, methodName, symbols)
	}
}

// extractRakeTask processes a `task :name do...end` call node.
func extractRakeTask(
	node *tree_sitter.Node,
	src []byte,
	file string,
	symbols *[]*treesitter.Symbol,
) {
	// Find the argument_list to get the task name
	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return
	}

	// First argument is the task name (simple_symbol like :build)
	taskName := ""
	for i := uint(0); i < argList.ChildCount(); i++ {
		child := argList.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "simple_symbol" {
			raw := nodeText(child, src)
			// Remove leading colon from symbol literal
			taskName = strings.TrimPrefix(raw, ":")
			break
		}
	}

	if taskName == "" {
		return
	}

	id := treesitter.SymbolID("task:" + taskName)
	sym := &treesitter.Symbol{
		ID:            id,
		Name:          "task:" + taskName,
		QualifiedName: "task:" + taskName,
		Language:      "ruby",
		File:          file,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolFunction,
	}
	*symbols = append(*symbols, sym)
}

// extractSinatraRoute processes a `get '/path' do...end` call node.
//
//nolint:gocognit // Sinatra route parsing requires checking for do_block and argument structure
func extractSinatraRoute(
	node *tree_sitter.Node,
	src []byte,
	file, method string,
	symbols *[]*treesitter.Symbol,
) {
	// Only treat as Sinatra route if it has a do_block (not a Rails route's to: hash arg)
	hasBlock := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "do_block" {
			hasBlock = true
			break
		}
	}
	if !hasBlock {
		return
	}

	// Extract path from first string argument
	argList := node.ChildByFieldName("arguments")
	path := ""
	if argList != nil {
		for i := uint(0); i < argList.ChildCount(); i++ {
			child := argList.Child(i)
			if child == nil {
				continue
			}
			if child.Kind() == "string" {
				path = extractStringContent(child, src)
				break
			}
		}
	}

	if path == "" {
		path = "/"
	}

	routeID := "sinatra:" + method + ":" + path
	id := treesitter.SymbolID(routeID)
	sym := &treesitter.Symbol{
		ID:            id,
		Name:          routeID,
		QualifiedName: routeID,
		Language:      "ruby",
		File:          file,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolFunction,
	}
	*symbols = append(*symbols, sym)
}

// extractStringContent returns the text inside a string node.
func extractStringContent(node *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "string_content" {
			return nodeText(child, src)
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveImports
// ─────────────────────────────────────────────────────────────────────────────

// ResolveImports walks the AST to find require and require_relative calls.
// Ruby: require 'gem_name', require_relative './local_file'
func (e *Extractor) ResolveImports(file string, src []byte, tree *tree_sitter.Tree, _ string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import
	collectImports(root, src, file, &imports)
	return imports, nil
}

// collectImports recursively visits nodes to find require/require_relative calls.
//
//nolint:gocognit // recursive visitor across multiple node kinds
func collectImports(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	if node == nil {
		return
	}

	if node.Kind() == "call" {
		if isRequireCall(node, src) {
			extractRequire(node, src, file, imports)
			return
		}
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		collectImports(node.Child(i), src, file, imports)
	}
}

// isRequireCall returns true if the call node is a require or require_relative call.
func isRequireCall(node *tree_sitter.Node, src []byte) bool {
	if node.ChildCount() == 0 {
		return false
	}
	first := node.Child(0)
	if first == nil {
		return false
	}
	name := nodeText(first, src)
	return name == "require" || name == "require_relative"
}

// extractRequire processes a require/require_relative call node.
func extractRequire(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return
	}

	for i := uint(0); i < argList.ChildCount(); i++ {
		child := argList.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "string" {
			moduleName := extractStringContent(child, src)
			if moduleName != "" {
				*imports = append(*imports, treesitter.Import{
					Module: moduleName,
					Alias:  moduleName,
					File:   file,
					Line:   rowToLine(node.StartPosition().Row),
				})
			}
			return
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractCalls
// ─────────────────────────────────────────────────────────────────────────────

// ExtractCalls walks the AST to find all method invocations and scope resolution calls.
func (e *Extractor) ExtractCalls(file string, src []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	root := tree.RootNode()
	var edges []treesitter.Edge
	collectCalls(root, src, file, nil, "", scope, &edges)
	return edges, nil
}

// collectCalls recursively visits nodes to find call edges.
//
//nolint:gocognit,gocyclo // AST walker handles class body, method body, and various call forms
func collectCalls(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	currentMethod string,
	scope *treesitter.Scope,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	kind := node.Kind()

	switch kind {
	case "class", "module":
		name := classOrModuleName(node, src)
		body := node.ChildByFieldName("body")
		if name == "" {
			if body != nil {
				collectCalls(body, src, file, scopeStack, currentMethod, scope, edges)
			}
			return
		}
		if body != nil {
			var nameParts []string
			if strings.Contains(name, "::") {
				nameParts = strings.Split(name, "::")
			} else {
				nameParts = []string{name}
			}
			newStack := append(append([]string{}, scopeStack...), nameParts...)
			collectCalls(body, src, file, newStack, currentMethod, scope, edges)
		}
		return

	case "method":
		methodName := methodNameFromNode(node, src)
		body := node.ChildByFieldName("body")
		if body != nil {
			collectCalls(body, src, file, scopeStack, methodName, scope, edges)
		}
		return

	case "singleton_method":
		methodName := singletonMethodName(node, src)
		body := node.ChildByFieldName("body")
		if body != nil {
			collectCalls(body, src, file, scopeStack, methodName, scope, edges)
		}
		return

	case "call", "command_call":
		processCall(node, src, file, scopeStack, currentMethod, scope, edges)
		// Recurse into arguments for nested calls
		args := node.ChildByFieldName("arguments")
		if args != nil {
			for i := uint(0); i < args.ChildCount(); i++ {
				collectCalls(args.Child(i), src, file, scopeStack, currentMethod, scope, edges)
			}
		}
		// Recurse into do_block if present
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child != nil && child.Kind() == "do_block" {
				collectCalls(child, src, file, scopeStack, currentMethod, scope, edges)
			}
		}
		return
	}

	// Generic recursion
	for i := uint(0); i < node.ChildCount(); i++ {
		collectCalls(node.Child(i), src, file, scopeStack, currentMethod, scope, edges)
	}
}

// resolveTarget attempts to resolve a call target using the scope's import aliases.
// It splits on "::" first, then ".", and looks up the prefix in the scope.
// If found, it returns the fully-qualified resolved name; otherwise the original target.
func resolveTarget(target string, scope *treesitter.Scope) string {
	if scope == nil {
		return target
	}
	// Try "::" separator first (Ruby scope resolution style)
	parts := strings.SplitN(target, "::", 2)
	if len(parts) == 2 {
		if resolved, ok := scope.LookupImport(parts[0]); ok {
			return resolved + "." + parts[1]
		}
		return target
	}
	// Try "." separator (dot-call style)
	parts = strings.SplitN(target, ".", 2)
	if len(parts) == 2 {
		if resolved, ok := scope.LookupImport(parts[0]); ok {
			return resolved + "." + parts[1]
		}
	}
	return target
}

// processCall handles a `call` node and emits the appropriate edge.
//
// Ruby call AST shapes:
//  1. Scope resolution call: Nokogiri::HTML(args)
//     → [constant "Nokogiri"] [:: "::"] [constant "HTML"] [argument_list]
//  2. Method call with receiver: obj.method(args)
//     → [receiver] [. "."] [identifier "method"] [argument_list]
//  3. Plain function call: render(args) / puts(args)
//     → [identifier "render"] [argument_list]
//
//nolint:gocognit,gocyclo // dispatches three call shapes with metaprogramming detection
func processCall(
	node *tree_sitter.Node,
	src []byte,
	file string,
	scopeStack []string,
	currentMethod string,
	scope *treesitter.Scope,
	edges *[]treesitter.Edge,
) {
	if node.ChildCount() == 0 {
		return
	}

	from := buildFrom(scopeStack, currentMethod, file)
	line := rowToLine(node.StartPosition().Row)

	firstChild := node.Child(0)
	if firstChild == nil {
		return
	}

	// Determine call shape by examining node structure
	switch {
	case isScopeResolutionCall(node, src):
		// Shape 1: Nokogiri::HTML(args)
		scopeName := nodeText(firstChild, src) // "Nokogiri"
		methodName := scopeResolutionMethod(node, src)
		if scopeName != "" && methodName != "" {
			raw := scopeName + "::" + methodName
			target := resolveTarget(raw, scope)
			*edges = append(*edges, treesitter.Edge{
				From:       from,
				To:         treesitter.SymbolID(target),
				Kind:       treesitter.EdgeDirect,
				Confidence: 1.0,
				File:       file,
				Line:       line,
			})
		}

	case isMethodCallWithReceiver(node, src):
		// Shape 2: obj.method(args)
		receiverText := nodeText(firstChild, src)
		methodName := dotCallMethodName(node, src)
		if receiverText == "" || methodName == "" {
			return
		}
		// Check for send/public_send metaprogramming
		if methodName == "send" || methodName == "public_send" {
			dispatchTarget := extractSendTarget(node, src)
			if dispatchTarget != "" {
				*edges = append(*edges, treesitter.Edge{
					From:       from,
					To:         treesitter.SymbolID(dispatchTarget),
					Kind:       treesitter.EdgeDispatch,
					Confidence: 0.3,
					File:       file,
					Line:       line,
				})
			}
			return
		}
		raw := receiverText + "::" + methodName
		target := resolveTarget(raw, scope)
		*edges = append(*edges, treesitter.Edge{
			From:       from,
			To:         treesitter.SymbolID(target),
			Kind:       treesitter.EdgeDirect,
			Confidence: 0.8,
			File:       file,
			Line:       line,
		})

	default:
		// Shape 3: plain function call — identifier is first child
		funcName := nodeText(firstChild, src)
		if funcName == "" {
			return
		}
		// Check for top-level send/public_send
		if funcName == "send" || funcName == "public_send" {
			dispatchTarget := extractSendTarget(node, src)
			if dispatchTarget != "" {
				*edges = append(*edges, treesitter.Edge{
					From:       from,
					To:         treesitter.SymbolID(dispatchTarget),
					Kind:       treesitter.EdgeDispatch,
					Confidence: 0.3,
					File:       file,
					Line:       line,
				})
			}
			return
		}
		// Skip require calls — they are handled in ResolveImports
		if funcName == "require" || funcName == "require_relative" {
			return
		}
		*edges = append(*edges, treesitter.Edge{
			From:       from,
			To:         treesitter.SymbolID(funcName),
			Kind:       treesitter.EdgeDirect,
			Confidence: 1.0,
			File:       file,
			Line:       line,
		})
	}
}

// isScopeResolutionCall returns true if the call node is a scope-resolution call like Nokogiri::HTML(args).
// In the Ruby AST this looks like: [constant] [::] [constant] [argument_list]
func isScopeResolutionCall(node *tree_sitter.Node, src []byte) bool {
	// We need to find a "::" token among the direct children
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "::" {
			return true
		}
	}
	return false
}

// scopeResolutionMethod returns the method name (second constant) in a Nokogiri::HTML call.
func scopeResolutionMethod(node *tree_sitter.Node, src []byte) string {
	// The method name is the constant after the "::" token
	sawSeparator := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "::" {
			sawSeparator = true
			continue
		}
		if sawSeparator && child.Kind() == "constant" {
			return nodeText(child, src)
		}
	}
	return ""
}

// isMethodCallWithReceiver returns true if the call node has a "." token (e.g. obj.method).
func isMethodCallWithReceiver(node *tree_sitter.Node, src []byte) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "." {
			return true
		}
	}
	return false
}

// dotCallMethodName returns the method name after "." in an obj.method call.
func dotCallMethodName(node *tree_sitter.Node, src []byte) string {
	sawDot := false
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "." {
			sawDot = true
			continue
		}
		if sawDot && child.Kind() == "identifier" {
			return nodeText(child, src)
		}
	}
	return ""
}

// extractSendTarget extracts the target method name from a send(:method) call.
// The first argument should be a symbol literal like :method_name.
func extractSendTarget(node *tree_sitter.Node, src []byte) string {
	argList := node.ChildByFieldName("arguments")
	if argList == nil {
		return ""
	}
	for i := uint(0); i < argList.ChildCount(); i++ {
		child := argList.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "simple_symbol" {
			raw := nodeText(child, src)
			return strings.TrimPrefix(raw, ":")
		}
	}
	return ""
}

// SnapshotState returns a deep copy of the current cross-file state.
// The returned value can be passed to RestoreState on any Extractor.
func (e *Extractor) SnapshotState() any {
	snap := newCrossFileState()
	for k, v := range e.state.Mixins {
		entries := make([]MixinEntry, len(v))
		copy(entries, v)
		snap.Mixins[k] = entries
	}
	for k, v := range e.state.Hierarchy {
		snap.Hierarchy[k] = v
	}
	for k, v := range e.state.ModuleMethods {
		methods := make([]string, len(v))
		copy(methods, v)
		snap.ModuleMethods[k] = methods
	}
	return snap
}

// RestoreState merges a snapshot (produced by SnapshotState) into this extractor's state.
// Entries already present are not duplicated (append-unique semantics).
//
//nolint:gocognit // pre-existing complexity from multi-map merge logic; refactoring deferred
func (e *Extractor) RestoreState(s any) {
	snap, ok := s.(*CrossFileState)
	if !ok {
		return
	}
	for k, entries := range snap.Mixins {
		for _, entry := range entries {
			if !containsMixin(e.state.Mixins[k], entry) {
				e.state.Mixins[k] = append(e.state.Mixins[k], entry)
			}
		}
	}
	for k, v := range snap.Hierarchy {
		if _, exists := e.state.Hierarchy[k]; !exists {
			e.state.Hierarchy[k] = v
		}
	}
	for k, methods := range snap.ModuleMethods {
		for _, m := range methods {
			if !containsString(e.state.ModuleMethods[k], m) {
				e.state.ModuleMethods[k] = append(e.state.ModuleMethods[k], m)
			}
		}
	}
}

// containsMixin returns true if entries already contains an entry with the same Module and Kind.
func containsMixin(entries []MixinEntry, entry MixinEntry) bool {
	for _, e := range entries {
		if e.Module == entry.Module && e.Kind == entry.Kind {
			return true
		}
	}
	return false
}

// containsString returns true if slice already contains s.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// buildFrom constructs the caller's SymbolID from the current context.
func buildFrom(scopeStack []string, currentMethod, file string) treesitter.SymbolID {
	className := strings.Join(scopeStack, "::")
	if className != "" && currentMethod != "" {
		return treesitter.SymbolID(className + "::" + currentMethod)
	}
	if className != "" {
		return treesitter.SymbolID(className)
	}
	if currentMethod != "" {
		return treesitter.SymbolID(currentMethod)
	}
	return treesitter.SymbolID(file)
}
