// Package javascript implements tree-sitter AST extraction for JavaScript and TypeScript source files.
// It extracts symbols (functions, methods, classes), imports, and call edges.
package javascript

import (
	"fmt"
	"path/filepath"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// Compile-time interface conformance check.
var _ treesitter.LanguageExtractor = (*Extractor)(nil)

// Extractor extracts symbols, imports, and call edges from JavaScript/TypeScript ASTs.
// It also tracks decorator/export metadata for entry point discovery.
type Extractor struct {
	// decorators maps SymbolID → decorator/annotation strings found on the definition.
	decorators map[treesitter.SymbolID][]string
	// exported tracks which SymbolIDs are exported (export keyword or module.exports).
	exported map[treesitter.SymbolID]bool
	// routeHandlers tracks unqualified symbol names registered as HTTP route callbacks.
	// E.g. app.get('/path', handleData) → "handleData" is recorded here.
	routeHandlers map[string]bool
}

// New creates a new JavaScript/TypeScript Extractor.
func New() *Extractor {
	return &Extractor{
		decorators:    make(map[treesitter.SymbolID][]string),
		exported:      make(map[treesitter.SymbolID]bool),
		routeHandlers: make(map[string]bool),
	}
}

// ModuleFromFile derives a module name from a JS/TS file path.
// "handler.js" → "handler", "routes/api.ts" → "api"
func ModuleFromFile(file string) string {
	base := filepath.Base(file)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	// Sanitize characters that are not valid in qualified names (e.g. SvelteKit "+server")
	name = strings.ReplaceAll(name, "+", "_")
	return name
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

// isArrowOrFunction returns true if the node is an arrow_function or function_expression.
func isArrowOrFunction(node *tree_sitter.Node) bool {
	if node == nil {
		return false
	}
	k := node.Kind()
	return k == "arrow_function" || k == "function_expression" || k == "function"
}

// isRequireCallSrc returns true if the node is a call to require() (with source bytes).
func isRequireCallSrc(node *tree_sitter.Node, src []byte) bool {
	if node == nil || node.Kind() != "call_expression" {
		return false
	}
	funcNode := node.ChildByFieldName("function")
	if funcNode == nil {
		return false
	}
	return nodeText(funcNode, src) == "require"
}

// stripQuotes removes surrounding single, double, or backtick quotes from a string token.
func stripQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	if (s[0] == '"' && s[len(s)-1] == '"') ||
		(s[0] == '\'' && s[len(s)-1] == '\'') ||
		(s[0] == '`' && s[len(s)-1] == '`') {
		return s[1 : len(s)-1]
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractSymbols
// ─────────────────────────────────────────────────────────────────────────────

// ExtractSymbols walks the AST to find all function, arrow function, and class definitions.
// Methods inside classes are annotated with SymbolMethod and a qualified name.
// Route handler registrations (app.get, app.post, …) are tracked in routeHandlers.
func (e *Extractor) ExtractSymbols(file string, src []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	// Reset per-call state to prevent accumulation across calls.
	e.decorators = make(map[treesitter.SymbolID][]string)
	e.exported = make(map[treesitter.SymbolID]bool)
	e.routeHandlers = make(map[string]bool)

	root := tree.RootNode()
	mod := ModuleFromFile(file)
	var symbols []*treesitter.Symbol
	walkSymbols(root, src, file, mod, "", &symbols, e.decorators, e.exported, e.routeHandlers)
	return symbols, nil
}

// symState bundles mutable state threaded through the symbol walker.
type symState struct {
	decorators    map[treesitter.SymbolID][]string
	exported      map[treesitter.SymbolID]bool
	routeHandlers map[string]bool
}

// walkSymbols recursively visits nodes to collect function/class definitions
// and detect route handler registrations.
//
//nolint:gocognit,gocyclo // AST walker must branch on many JS/TS definition kinds
func walkSymbols(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	decorators map[treesitter.SymbolID][]string,
	exported map[treesitter.SymbolID]bool,
	routeHandlers map[string]bool,
) {
	if node == nil {
		return
	}

	st := symState{decorators: decorators, exported: exported, routeHandlers: routeHandlers}

	switch node.Kind() {
	case "function_declaration":
		extractFunctionDecl(node, src, file, moduleName, className, symbols, st, nil, false)
		return

	case "class_declaration":
		extractClassDecl(node, src, file, moduleName, symbols, st, nil, false)
		return

	case "lexical_declaration", "variable_declaration":
		extractVarDecl(node, src, file, moduleName, className, symbols, st)
		return

	case "export_statement":
		extractExportStatement(node, src, file, moduleName, className, symbols, st)
		return

	case "expression_statement":
		// Detect route registrations: app.get('/p', handler) / app.post('/p', handler)
		// Also extract inline arrow function arguments as route handler symbols.
		detectRouteHandlers(node, src, routeHandlers)
		detectAndExtractInlineRouteHandlers(node, src, file, moduleName, symbols, exported, routeHandlers)
		// Detect module.exports = { ... } / module.exports.foo = fn assignments.
		detectModuleExports(node, src, moduleName, symbols, exported)
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			walkSymbols(child, src, file, moduleName, className, symbols, decorators, exported, routeHandlers)
		}
		return

	default:
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			walkSymbols(child, src, file, moduleName, className, symbols, decorators, exported, routeHandlers)
		}
	}
}

// detectRouteHandlers inspects an expression_statement to find router method calls
// such as app.get('/path', handler) or router.post('/path', fn) and records the
// handler identifier in routeHandlers.
//
//nolint:gocognit,gocyclo // route detection inspects nested call argument lists
func detectRouteHandlers(node *tree_sitter.Node, src []byte, routeHandlers map[string]bool) {
	if node == nil {
		return
	}
	// Look for a call_expression child
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "call_expression" {
			continue
		}
		funcNode := child.ChildByFieldName("function")
		if funcNode == nil || funcNode.Kind() != "member_expression" {
			continue
		}
		// Check the method name is an HTTP verb
		propNode := funcNode.ChildByFieldName("property")
		if propNode == nil {
			continue
		}
		method := strings.ToLower(nodeText(propNode, src))
		if !isHTTPRouteMethod(method) {
			continue
		}
		// The last identifier argument(s) after the path string are handlers
		argsNode := child.ChildByFieldName("arguments")
		if argsNode == nil {
			continue
		}
		for j := uint(0); j < argsNode.ChildCount(); j++ {
			arg := argsNode.Child(j)
			if arg == nil {
				continue
			}
			if arg.Kind() == "identifier" {
				name := nodeText(arg, src)
				if name != "" {
					routeHandlers[name] = true
				}
			}
		}
	}
}

// routeRegistrationMethods is the unified set of HTTP/router method names used by Express/Hono/Fastify-style routers.
// It includes standard HTTP verbs plus Express middleware methods ("use", "route").
var routeRegistrationMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true, "all": true,
	"use": true, "route": true,
}

// isHTTPRouteMethod returns true if the method name is a route registration method used by Express/Hono/Fastify.
func isHTTPRouteMethod(method string) bool {
	return routeRegistrationMethods[method]
}

// detectAndExtractInlineRouteHandlers extracts anonymous arrow function arguments of
// HTTP route registrations (e.g. app.get('/path', (c) => {...})) as synthetic symbols
// and marks them as route handlers.
//
//nolint:gocognit,gocyclo // needs to inspect nested call arg list for arrow functions
func detectAndExtractInlineRouteHandlers(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName string,
	symbols *[]*treesitter.Symbol,
	exported map[treesitter.SymbolID]bool,
	routeHandlers map[string]bool,
) {
	if node == nil {
		return
	}
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "call_expression" {
			continue
		}
		funcNode := child.ChildByFieldName("function")
		if funcNode == nil || funcNode.Kind() != "member_expression" {
			continue
		}
		propNode := funcNode.ChildByFieldName("property")
		if propNode == nil {
			continue
		}
		method := strings.ToLower(nodeText(propNode, src))
		if !isHTTPRouteMethod(method) {
			continue
		}
		argsNode := child.ChildByFieldName("arguments")
		if argsNode == nil {
			continue
		}
		// Extract inline arrow/function arguments as route handler symbols.
		argIdx := uint(0)
		for j := uint(0); j < argsNode.ChildCount(); j++ {
			arg := argsNode.Child(j)
			if arg == nil {
				continue
			}
			if !isArrowOrFunction(arg) {
				continue
			}
			// Generate a synthetic name for the inline handler.
			syntheticName := "_routeHandler_" + method + "_" + fmt.Sprint(argIdx)
			argIdx++
			qualifiedName := moduleName + "." + syntheticName
			id := treesitter.SymbolID(qualifiedName)
			exported[id] = true
			routeHandlers[syntheticName] = true
			*symbols = append(*symbols, &treesitter.Symbol{
				ID:            id,
				Name:          syntheticName,
				QualifiedName: qualifiedName,
				Language:      "javascript",
				File:          file,
				Package:       moduleName,
				StartLine:     rowToLine(arg.StartPosition().Row),
				EndLine:       rowToLine(arg.EndPosition().Row),
				Kind:          treesitter.SymbolFunction,
			})
		}
	}
}

// detectModuleExports detects CommonJS module.exports = { ... } and module.exports.foo = fn
// assignments and marks the referenced names in the exported map.
//
//nolint:gocognit,gocyclo // handles object literal, identifier, and property assignment forms
func detectModuleExports(
	node *tree_sitter.Node,
	src []byte,
	moduleName string,
	symbols *[]*treesitter.Symbol,
	exported map[treesitter.SymbolID]bool,
) {
	if node == nil {
		return
	}
	// Look for: expression_statement > assignment_expression
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "assignment_expression" {
			continue
		}
		leftNode := child.ChildByFieldName("left")
		rightNode := child.ChildByFieldName("right")
		if leftNode == nil || rightNode == nil {
			continue
		}

		leftText := nodeText(leftNode, src)

		// Case 1: module.exports = { foo, Bar, ... }
		if leftText == "module.exports" && rightNode.Kind() == "object" {
			for j := uint(0); j < rightNode.ChildCount(); j++ {
				prop := rightNode.Child(j)
				if prop == nil {
					continue
				}
				var name string
				switch prop.Kind() {
				case "shorthand_property_identifier", "shorthand_property_identifier_pattern", "identifier":
					name = nodeText(prop, src)
				case "pair":
					keyNode := prop.ChildByFieldName("key")
					if keyNode != nil {
						name = nodeText(keyNode, src)
					}
				}
				if name != "" {
					exported[treesitter.SymbolID(moduleName+"."+name)] = true
				}
			}
			continue
		}

		// Case 2: module.exports = identifier
		if leftText == "module.exports" && rightNode.Kind() == "identifier" {
			name := nodeText(rightNode, src)
			if name != "" {
				exported[treesitter.SymbolID(moduleName+"."+name)] = true
			}
			continue
		}

		// Case 3: module.exports.foo = fn
		if leftNode.Kind() == "member_expression" {
			objNode := leftNode.ChildByFieldName("object")
			propNode := leftNode.ChildByFieldName("property")
			if objNode != nil && propNode != nil && nodeText(objNode, src) == "module.exports" {
				name := nodeText(propNode, src)
				if name != "" {
					exported[treesitter.SymbolID(moduleName+"."+name)] = true
					// Also record the symbol if it is an inline function.
					_ = symbols // symbol extraction handled by walkSymbols; export is sufficient here
				}
			}
		}
	}
}

// extractFunctionDecl extracts a function_declaration node as a symbol.
func extractFunctionDecl(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	st symState,
	decs []string,
	isExported bool,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nodeText(nameNode, src)
	if name == "" {
		return
	}

	symKind := treesitter.SymbolFunction
	qualifiedName := moduleName + "." + name
	if className != "" {
		symKind = treesitter.SymbolMethod
		qualifiedName = moduleName + "." + className + "." + name
	}

	id := treesitter.SymbolID(qualifiedName)
	if len(decs) > 0 {
		st.decorators[id] = decs
	}
	if isExported {
		st.exported[id] = true
	}

	*symbols = append(*symbols, &treesitter.Symbol{
		ID:            id,
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "javascript",
		File:          file,
		Package:       moduleName,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          symKind,
	})

	// Recurse into body for nested definitions.
	bodyNode := node.ChildByFieldName("body")
	if bodyNode != nil {
		walkSymbols(bodyNode, src, file, moduleName, className, symbols, st.decorators, st.exported, st.routeHandlers)
	}
}

// extractClassDecl extracts a class_declaration node and recurses into its body.
func extractClassDecl(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName string,
	symbols *[]*treesitter.Symbol,
	st symState,
	decs []string,
	isExported bool,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nodeText(nameNode, src)
	if name == "" {
		return
	}

	qualifiedName := moduleName + "." + name
	id := treesitter.SymbolID(qualifiedName)
	if len(decs) > 0 {
		st.decorators[id] = decs
	}
	if isExported {
		st.exported[id] = true
	}

	*symbols = append(*symbols, &treesitter.Symbol{
		ID:            id,
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "javascript",
		File:          file,
		Package:       moduleName,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
	})

	bodyNode := node.ChildByFieldName("body")
	if bodyNode != nil {
		walkClassBody(bodyNode, src, file, moduleName, name, symbols, st)
	}
}

// walkClassBody visits class body nodes to extract method definitions.
//
//nolint:gocognit,gocyclo // handles method_definition, decorator look-ahead, and field variants
func walkClassBody(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	st symState,
) {
	if node == nil {
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		switch child.Kind() {
		case "method_definition":
			extractMethodDef(child, src, file, moduleName, className, symbols, st.decorators, nil)

		case "decorator":
			// Collect consecutive decorators then apply to the next method_definition.
			var decs []string
			decs = append(decs, nodeText(child, src))
			for j := i + 1; j < node.ChildCount(); j++ {
				next := node.Child(j)
				if next == nil {
					continue
				}
				if next.Kind() == "decorator" {
					decs = append(decs, nodeText(next, src))
					i = j
					continue
				}
				if next.Kind() == "method_definition" {
					extractMethodDef(next, src, file, moduleName, className, symbols, st.decorators, decs)
					i = j
				}
				break
			}

		case "public_field_definition":
			// class field arrow: foo = () => {}
			nameNode := child.ChildByFieldName("name")
			valueNode := child.ChildByFieldName("value")
			if nameNode != nil && valueNode != nil && isArrowOrFunction(valueNode) {
				name := nodeText(nameNode, src)
				qualifiedName := moduleName + "." + className + "." + name
				id := treesitter.SymbolID(qualifiedName)
				*symbols = append(*symbols, &treesitter.Symbol{
					ID:            id,
					Name:          name,
					QualifiedName: qualifiedName,
					Language:      "javascript",
					File:          file,
					Package:       moduleName,
					StartLine:     rowToLine(child.StartPosition().Row),
					EndLine:       rowToLine(child.EndPosition().Row),
					Kind:          treesitter.SymbolMethod,
				})
			}
		}
	}
}

// extractMethodDef extracts a method_definition node.
func extractMethodDef(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	decorators map[treesitter.SymbolID][]string,
	decs []string,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nodeText(nameNode, src)
	if name == "" {
		return
	}

	qualifiedName := moduleName + "." + className + "." + name
	id := treesitter.SymbolID(qualifiedName)
	if len(decs) > 0 {
		decorators[id] = decs
	}

	*symbols = append(*symbols, &treesitter.Symbol{
		ID:            id,
		Name:          name,
		QualifiedName: qualifiedName,
		Language:      "javascript",
		File:          file,
		Package:       moduleName,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolMethod,
	})
}

// extractVarDecl handles const/let/var declarations containing arrow/function expressions.
//
//nolint:gocognit // handles many var/const declaration binding patterns
func extractVarDecl(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	st symState,
) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "variable_declarator" {
			continue
		}
		nameNode := child.ChildByFieldName("name")
		valueNode := child.ChildByFieldName("value")
		if nameNode == nil || valueNode == nil {
			continue
		}

		if !isArrowOrFunction(valueNode) {
			continue
		}

		name := nodeText(nameNode, src)
		if name == "" {
			continue
		}
		symKind := treesitter.SymbolFunction
		qualifiedName := moduleName + "." + name
		if className != "" {
			symKind = treesitter.SymbolMethod
			qualifiedName = moduleName + "." + className + "." + name
		}
		id := treesitter.SymbolID(qualifiedName)
		// st.exported[id] may already be set by the caller (e.g. extractExportStatement); preserve it.
		*symbols = append(*symbols, &treesitter.Symbol{
			ID:            id,
			Name:          name,
			QualifiedName: qualifiedName,
			Language:      "javascript",
			File:          file,
			Package:       moduleName,
			StartLine:     rowToLine(child.StartPosition().Row),
			EndLine:       rowToLine(child.EndPosition().Row),
			Kind:          symKind,
		})
	}
}

// extractExportStatement handles all forms of export declarations.
//
//nolint:gocognit,gocyclo // handles default, named function, class, const, call expression exports
func extractExportStatement(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	st symState,
) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		switch child.Kind() {
		case "function_declaration":
			extractFunctionDecl(child, src, file, moduleName, className, symbols, st, nil, true)

		case "class_declaration":
			extractClassDecl(child, src, file, moduleName, symbols, st, nil, true)

		case "lexical_declaration", "variable_declaration":
			extractVarDecl(child, src, file, moduleName, className, symbols, st)
			// Mark the bound names as exported.
			for j := uint(0); j < child.ChildCount(); j++ {
				decl := child.Child(j)
				if decl == nil || decl.Kind() != "variable_declarator" {
					continue
				}
				nameNode := decl.ChildByFieldName("name")
				if nameNode != nil {
					name := nodeText(nameNode, src)
					id := treesitter.SymbolID(moduleName + "." + name)
					st.exported[id] = true
				}
			}

		case "call_expression":
			// export default defineEventHandler(...)  ← Nuxt
			funcNode := child.ChildByFieldName("function")
			if funcNode != nil {
				calleeName := nodeText(funcNode, src)
				if calleeName != "" {
					id := treesitter.SymbolID(moduleName + "." + calleeName)
					st.exported[id] = true
					*symbols = append(*symbols, &treesitter.Symbol{
						ID:            id,
						Name:          calleeName,
						QualifiedName: moduleName + "." + calleeName,
						Language:      "javascript",
						File:          file,
						Package:       moduleName,
						StartLine:     rowToLine(child.StartPosition().Row),
						EndLine:       rowToLine(child.EndPosition().Row),
						Kind:          treesitter.SymbolFunction,
					})
				}
			}

		case "arrow_function", "function_expression":
			// export default (req, res) => {}
			qualifiedName := moduleName + ".<default>"
			id := treesitter.SymbolID(qualifiedName)
			st.exported[id] = true
			*symbols = append(*symbols, &treesitter.Symbol{
				ID:            id,
				Name:          "<default>",
				QualifiedName: qualifiedName,
				Language:      "javascript",
				File:          file,
				Package:       moduleName,
				StartLine:     rowToLine(child.StartPosition().Row),
				EndLine:       rowToLine(child.EndPosition().Row),
				Kind:          treesitter.SymbolFunction,
			})
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolveImports
// ─────────────────────────────────────────────────────────────────────────────

// ResolveImports walks the AST to find all import statements (ESM and CommonJS).
func (e *Extractor) ResolveImports(file string, src []byte, tree *tree_sitter.Tree, _ string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import
	collectImports(root, src, file, &imports)
	return imports, nil
}

// collectImports recursively finds import_statement (ESM) and require() call nodes (CJS).
//
//nolint:gocognit,gocyclo // JS import grammar has many variations requiring extensive branching
func collectImports(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	if node == nil {
		return
	}

	switch node.Kind() {
	case "import_statement":
		collectESMImport(node, src, file, imports)
		return

	case "variable_declarator":
		valueNode := node.ChildByFieldName("value")
		if valueNode != nil && isRequireCallSrc(valueNode, src) {
			collectRequireImport(node, src, file, imports)
		}
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectImports(child, src, file, imports)
	}
}

// collectESMImport parses an import_statement node.
//
//nolint:gocognit,gocyclo // ESM import has many clause forms
func collectESMImport(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	sourceNode := node.ChildByFieldName("source")
	if sourceNode == nil {
		return
	}
	module := stripQuotes(nodeText(sourceNode, src))
	if module == "" {
		return
	}

	imp := treesitter.Import{
		Module: module,
		File:   file,
		Line:   rowToLine(node.StartPosition().Row),
	}

	// Find import_clause
	var clauseNode *tree_sitter.Node
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child != nil && child.Kind() == "import_clause" {
			clauseNode = child
			break
		}
	}
	if clauseNode != nil {
		parseImportClause(clauseNode, src, &imp)
	}

	*imports = append(*imports, imp)
}

// parseImportClause extracts bindings from an import_clause node.
//
//nolint:gocognit,gocyclo // handles identifier (default), named_imports, namespace_import
func parseImportClause(node *tree_sitter.Node, src []byte, imp *treesitter.Import) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Kind() {
		case "identifier":
			imp.Alias = nodeText(child, src)
		case "named_imports":
			for j := uint(0); j < child.ChildCount(); j++ {
				specifier := child.Child(j)
				if specifier == nil || specifier.Kind() != "import_specifier" {
					continue
				}
				nameNode := specifier.ChildByFieldName("name")
				if nameNode != nil {
					imp.Symbols = append(imp.Symbols, nodeText(nameNode, src))
				}
			}
		case "namespace_import":
			for j := uint(0); j < child.ChildCount(); j++ {
				nsChild := child.Child(j)
				if nsChild != nil && nsChild.Kind() == "identifier" {
					imp.Alias = nodeText(nsChild, src)
				}
			}
		}
	}
}

// collectRequireImport extracts the module from a variable_declarator with require().
//
//nolint:gocognit,gocyclo // handles simple binding and destructuring patterns
func collectRequireImport(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")
	if nameNode == nil || valueNode == nil {
		return
	}

	argsNode := valueNode.ChildByFieldName("arguments")
	if argsNode == nil {
		return
	}
	module := ""
	for i := uint(0); i < argsNode.ChildCount(); i++ {
		child := argsNode.Child(i)
		if child != nil && (child.Kind() == "string" || child.Kind() == "template_string") {
			module = stripQuotes(nodeText(child, src))
			break
		}
	}
	if module == "" {
		return
	}

	imp := treesitter.Import{
		Module: module,
		File:   file,
		Line:   rowToLine(node.StartPosition().Row),
	}

	switch nameNode.Kind() {
	case "identifier":
		imp.Alias = nodeText(nameNode, src)
	case "object_pattern":
		for i := uint(0); i < nameNode.ChildCount(); i++ {
			child := nameNode.Child(i)
			if child == nil {
				continue
			}
			switch child.Kind() {
			case "shorthand_property_identifier_pattern":
				imp.Symbols = append(imp.Symbols, nodeText(child, src))
			case "pair_pattern":
				valNode := child.ChildByFieldName("value")
				if valNode != nil {
					imp.Symbols = append(imp.Symbols, nodeText(valNode, src))
				}
			}
		}
	}

	*imports = append(*imports, imp)
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractCalls
// ─────────────────────────────────────────────────────────────────────────────

// ExtractCalls walks the AST to find all call expressions and produces call edges.
// Typed vars are collected per-function from parameter annotations; file-level declarations are not tracked.
func (e *Extractor) ExtractCalls(file string, src []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	root := tree.RootNode()
	mod := ModuleFromFile(file)
	var edges []treesitter.Edge
	// Typed vars are collected per-function from parameter annotations; file-level declarations are not tracked.
	typedVars := make(map[string]bool)
	collectCalls(root, src, file, mod, "", scope, typedVars, &edges)
	return edges, nil
}

//nolint:gocognit,gocyclo // inspects multiple TS node kinds for type annotations
func collectTypedVarsNode(node *tree_sitter.Node, src []byte, typed map[string]bool) {
	if node == nil {
		return
	}
	switch node.Kind() {
	case "variable_declarator":
		nameNode := node.ChildByFieldName("name")
		// Check for a type_annotation sibling child.
		hasType := false
		for i := uint(0); i < node.ChildCount(); i++ {
			if child := node.Child(i); child != nil && child.Kind() == "type_annotation" {
				hasType = true
				break
			}
		}
		if hasType && nameNode != nil {
			name := nodeText(nameNode, src)
			if name != "" {
				typed[name] = true
			}
		}
	case "required_parameter", "optional_parameter":
		// TypeScript function parameters: (param: Type)
		nameNode := node.ChildByFieldName("pattern")
		hasType := false
		for i := uint(0); i < node.ChildCount(); i++ {
			if child := node.Child(i); child != nil && child.Kind() == "type_annotation" {
				hasType = true
				break
			}
		}
		if hasType && nameNode != nil {
			name := nodeText(nameNode, src)
			if name != "" {
				typed[name] = true
			}
		}
	}
	for i := uint(0); i < node.ChildCount(); i++ {
		collectTypedVarsNode(node.Child(i), src, typed)
	}
}

// collectCalls recursively visits nodes to find call expressions.
//
//nolint:gocognit,gocyclo // call extraction must traverse many JS node kinds
func collectCalls(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, currentFunc string,
	scope *treesitter.Scope,
	typedVars map[string]bool,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	switch node.Kind() {
	case "function_declaration":
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			name := nodeText(nameNode, src)
			newFunc := moduleName + "." + name
			// Collect typed vars scoped to this function's parameters only.
			funcTypedVars := collectTypedVarsFromParams(node, src)
			if bodyNode := node.ChildByFieldName("body"); bodyNode != nil {
				collectCalls(bodyNode, src, file, moduleName, newFunc, scope, funcTypedVars, edges)
			}
		}
		return

	case "class_declaration":
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			className := nodeText(nameNode, src)
			if bodyNode := node.ChildByFieldName("body"); bodyNode != nil {
				collectCallsInClass(bodyNode, src, file, moduleName, className, scope, typedVars, edges)
			}
		}
		return

	case "method_definition":
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			name := nodeText(nameNode, src)
			methodFunc := moduleName + "." + name
			// Collect typed vars scoped to this method's parameters only.
			methodTypedVars := collectTypedVarsFromParams(node, src)
			if bodyNode := node.ChildByFieldName("body"); bodyNode != nil {
				collectCalls(bodyNode, src, file, moduleName, methodFunc, scope, methodTypedVars, edges)
			}
		}
		return

	case "lexical_declaration", "variable_declaration":
		// const foo = () => {}  — use binding name as the enclosing function context.
		// const x = someCall() — recurse into the value to capture the call.
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child == nil || child.Kind() != "variable_declarator" {
				continue
			}
			nameNode := child.ChildByFieldName("name")
			valueNode := child.ChildByFieldName("value")
			if nameNode == nil || valueNode == nil {
				continue
			}
			if isArrowOrFunction(valueNode) {
				name := nodeText(nameNode, src)
				newFunc := moduleName + "." + name
				// Collect typed vars scoped to this arrow/function's parameters only.
				arrowTypedVars := collectTypedVarsFromParams(valueNode, src)
				if bodyNode := valueNode.ChildByFieldName("body"); bodyNode != nil {
					collectCalls(bodyNode, src, file, moduleName, newFunc, scope, arrowTypedVars, edges)
				} else {
					// Single-expression arrow: (x) => expr
					collectCalls(valueNode, src, file, moduleName, newFunc, scope, arrowTypedVars, edges)
				}
			} else {
				// Non-function value — recurse to capture any call expressions inside.
				collectCalls(valueNode, src, file, moduleName, currentFunc, scope, typedVars, edges)
			}
		}
		return

	case "export_statement":
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			collectCalls(child, src, file, moduleName, currentFunc, scope, typedVars, edges)
		}
		return

	case "call_expression":
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			callee := resolveCallee(funcNode, src)
			if callee != "" {
				// Resolve CJS/ESM import aliases: if callee is "alias.method" and "alias"
				// is a known import alias in scope, rewrite to "module.method".
				callee = resolveAliasInCallee(callee, scope)
				from := treesitter.SymbolID(currentFunc)
				if currentFunc == "" {
					from = treesitter.SymbolID(moduleName)
				}
				conf := callConfidence(funcNode, src, typedVars)
				*edges = append(*edges, treesitter.Edge{
					From:       from,
					To:         treesitter.SymbolID(callee),
					Kind:       treesitter.EdgeDirect,
					Confidence: conf,
					File:       file,
					Line:       rowToLine(node.StartPosition().Row),
				})
			}
		}
		// Recurse into arguments to capture inline lambdas.
		if argsNode := node.ChildByFieldName("arguments"); argsNode != nil {
			collectCalls(argsNode, src, file, moduleName, currentFunc, scope, typedVars, edges)
		}
		return

	case "new_expression":
		// new Foo() / new http.Server()
		if constructorNode := node.ChildByFieldName("constructor"); constructorNode != nil {
			callee := resolveCallee(constructorNode, src)
			if callee != "" {
				from := treesitter.SymbolID(currentFunc)
				if currentFunc == "" {
					from = treesitter.SymbolID(moduleName)
				}
				*edges = append(*edges, treesitter.Edge{
					From:       from,
					To:         treesitter.SymbolID(callee),
					Kind:       treesitter.EdgeDirect,
					Confidence: 1.0,
					File:       file,
					Line:       rowToLine(node.StartPosition().Row),
				})
			}
		}
		if argsNode := node.ChildByFieldName("arguments"); argsNode != nil {
			collectCalls(argsNode, src, file, moduleName, currentFunc, scope, typedVars, edges)
		}
		return
	}

	// Default: recurse into all children.
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectCalls(child, src, file, moduleName, currentFunc, scope, typedVars, edges)
	}
}

// callConfidence returns 1.0 for direct calls and for member calls on typed variables,
// and 0.8 for member calls on unresolved (untyped) receivers.
func callConfidence(funcNode *tree_sitter.Node, src []byte, typedVars map[string]bool) float64 {
	if funcNode == nil || funcNode.Kind() != "member_expression" {
		return 1.0
	}
	objNode := funcNode.ChildByFieldName("object")
	if objNode == nil {
		return 0.8
	}
	// If the receiver is a typed variable, we have high confidence.
	receiverName := nodeText(objNode, src)
	if typedVars[receiverName] {
		return 1.0
	}
	return 0.8
}

// collectTypedVarsFromParams returns the set of parameter names that have explicit type annotations
// in the given function/method/arrow_function node. Only direct parameters are inspected (not body).
func collectTypedVarsFromParams(fnNode *tree_sitter.Node, src []byte) map[string]bool {
	typed := make(map[string]bool)
	if fnNode == nil {
		return typed
	}
	paramsNode := fnNode.ChildByFieldName("parameters")
	if paramsNode == nil {
		return typed
	}
	collectTypedVarsNode(paramsNode, src, typed)
	return typed
}

// collectCallsInClass handles call extraction inside a class body.
func collectCallsInClass(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	scope *treesitter.Scope,
	typedVars map[string]bool,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	if node.Kind() == "method_definition" {
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			name := nodeText(nameNode, src)
			methodFunc := moduleName + "." + className + "." + name
			if bodyNode := node.ChildByFieldName("body"); bodyNode != nil {
				collectCalls(bodyNode, src, file, moduleName, methodFunc, scope, typedVars, edges)
			}
		}
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectCallsInClass(child, src, file, moduleName, className, scope, typedVars, edges)
	}
}

// resolveAliasInCallee rewrites a callee string by resolving the leading object name against
// known import aliases in scope. For example, if scope has DefineImport("_", "lodash", ...),
// then "_.template" becomes "lodash.template". If the object part is not a known alias,
// the callee is returned unchanged.
func resolveAliasInCallee(callee string, scope *treesitter.Scope) string {
	if scope == nil {
		return callee
	}
	dotIdx := strings.Index(callee, ".")
	if dotIdx < 0 {
		// Plain identifier — not a member call; check if it is itself an import alias.
		if mod, ok := scope.LookupImport(callee); ok {
			return mod
		}
		return callee
	}
	obj := callee[:dotIdx]
	rest := callee[dotIdx:] // includes the leading "."
	if mod, ok := scope.LookupImport(obj); ok {
		return mod + rest
	}
	return callee
}

// resolveCallee extracts the callee name from a call's function node.
//
//nolint:gocognit,gocyclo // handles member_expression, identifier, chained call_expression, and await
func resolveCallee(node *tree_sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}

	switch node.Kind() {
	case "member_expression":
		objNode := node.ChildByFieldName("object")
		propNode := node.ChildByFieldName("property")
		if objNode != nil && propNode != nil {
			obj := resolveCallee(objNode, src)
			prop := nodeText(propNode, src)
			if obj != "" {
				return obj + "." + prop
			}
			return prop
		}

	case "identifier":
		return nodeText(node, src)

	case "call_expression":
		if funcNode := node.ChildByFieldName("function"); funcNode != nil {
			return resolveCallee(funcNode, src)
		}

	case "await_expression":
		for i := uint(0); i < node.ChildCount(); i++ {
			if child := node.Child(i); child != nil {
				return resolveCallee(child, src)
			}
		}
	}

	return ""
}
