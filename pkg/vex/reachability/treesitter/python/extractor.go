// Package python implements tree-sitter AST extraction for Python source files.
// It extracts symbols (functions, methods, classes), imports, and call edges.
package python

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

// Extractor extracts symbols, imports, and call edges from Python ASTs.
// It also tracks decorator metadata for entry point discovery.
type Extractor struct {
	// decorators maps SymbolID → decorator strings found before the definition.
	decorators map[treesitter.SymbolID][]string
}

// New creates a new Python Extractor.
func New() *Extractor {
	return &Extractor{
		decorators: make(map[treesitter.SymbolID][]string),
	}
}

// moduleFromFile derives the Python module name from a file path.
// "handler.py" → "handler", "pkg/utils.py" → "utils"
func moduleFromFile(file string) string {
	base := filepath.Base(file)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

// nodeText returns the UTF-8 text of a node.
func nodeText(n *tree_sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(src)
}

// rowToLine converts a tree-sitter 0-based row to a 1-based line number.
// Tree-sitter uses uint for rows; source files never exceed max int lines.
func rowToLine(row uint) int {
	return int(row) + 1 //nolint:gosec // row is a line number, never overflows int
}

// ExtractSymbols walks the AST to find all function and class definitions.
// Methods inside classes are annotated with SymbolMethod and a qualified name.
func (e *Extractor) ExtractSymbols(file string, src []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	e.decorators = make(map[treesitter.SymbolID][]string) // reset per call to prevent state accumulation
	root := tree.RootNode()
	mod := moduleFromFile(file)
	var symbols []*treesitter.Symbol
	walkSymbols(root, src, file, mod, "", &symbols, e.decorators)
	return symbols, nil
}

// walkSymbolsWithDecorators processes a function_definition or class_definition node,
// using the provided decorators (already collected from a parent decorated_definition).
//
//nolint:gocognit,gocyclo // handles two definition kinds with decorator and body traversal
func walkSymbolsWithDecorators(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	decoratorMap map[treesitter.SymbolID][]string,
	decs []string,
) {
	if node == nil {
		return
	}
	switch node.Kind() {
	case "function_definition":
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		name := nodeText(nameNode, src)

		symKind := treesitter.SymbolFunction
		qualifiedName := moduleName + "." + name
		if className != "" {
			symKind = treesitter.SymbolMethod
			qualifiedName = moduleName + "." + className + "." + name
		}

		id := treesitter.SymbolID(qualifiedName)
		if len(decs) > 0 {
			decoratorMap[id] = decs
		}

		sym := &treesitter.Symbol{
			ID:            id,
			Name:          name,
			QualifiedName: qualifiedName,
			Language:      "python",
			File:          file,
			Package:       moduleName,
			StartLine:     rowToLine(node.StartPosition().Row),
			EndLine:       rowToLine(node.EndPosition().Row),
			Kind:          symKind,
		}
		*symbols = append(*symbols, sym)

		bodyNode := node.ChildByFieldName("body")
		if bodyNode != nil {
			walkSymbols(bodyNode, src, file, moduleName, className, symbols, decoratorMap)
		}

	case "class_definition":
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		name := nodeText(nameNode, src)
		qualifiedName := moduleName + "." + name
		id := treesitter.SymbolID(qualifiedName)
		if len(decs) > 0 {
			decoratorMap[id] = decs
		}

		sym := &treesitter.Symbol{
			ID:            id,
			Name:          name,
			QualifiedName: qualifiedName,
			Language:      "python",
			File:          file,
			Package:       moduleName,
			StartLine:     rowToLine(node.StartPosition().Row),
			EndLine:       rowToLine(node.EndPosition().Row),
			Kind:          treesitter.SymbolClass,
		}
		*symbols = append(*symbols, sym)

		bodyNode := node.ChildByFieldName("body")
		if bodyNode != nil {
			walkSymbols(bodyNode, src, file, moduleName, name, symbols, decoratorMap)
		}
	}
}

// walkSymbols recursively visits nodes to collect function/class definitions.
//
//nolint:gocognit,gocyclo // AST walker must branch on decorated_definition, function_definition, class_definition
func walkSymbols(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	symbols *[]*treesitter.Symbol,
	decoratorMap map[treesitter.SymbolID][]string,
) {
	if node == nil {
		return
	}

	kind := node.Kind()

	switch kind {
	case "decorated_definition":
		// Python wraps decorated defs in a decorated_definition node.
		// Collect all decorators and then process the inner definition.
		var decs []string
		var defNode *tree_sitter.Node
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			switch child.Kind() {
			case "decorator":
				decs = append(decs, nodeText(child, src))
			case "function_definition", "class_definition":
				defNode = child
			}
		}
		if defNode != nil {
			walkSymbolsWithDecorators(defNode, src, file, moduleName, className, symbols, decoratorMap, decs)
		}
		return

	case "function_definition":
		walkSymbolsWithDecorators(node, src, file, moduleName, className, symbols, decoratorMap, nil)
		return

	case "class_definition":
		walkSymbolsWithDecorators(node, src, file, moduleName, className, symbols, decoratorMap, nil)
		return
	}

	// Recurse into all children for other node types
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		walkSymbols(child, src, file, moduleName, className, symbols, decoratorMap)
	}
}

// ResolveImports walks the AST to find all import statements.
func (e *Extractor) ResolveImports(file string, src []byte, tree *tree_sitter.Tree, _ string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import
	collectImports(root, src, file, &imports)
	return imports, nil
}

// collectImports recursively finds import_statement and import_from_statement nodes.
//
//nolint:gocognit,gocyclo // Python's import grammar has many variations requiring extensive branching
func collectImports(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	if node == nil {
		return
	}

	switch node.Kind() {
	case "import_statement":
		// import yaml, import os.path, import yaml as y
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			var moduleName, alias string
			switch child.Kind() {
			case "aliased_import":
				// import yaml as y
				nameNode := child.ChildByFieldName("name")
				aliasNode := child.ChildByFieldName("alias")
				if nameNode != nil {
					moduleName = nodeText(nameNode, src)
				}
				if aliasNode != nil {
					alias = nodeText(aliasNode, src)
				}
			case "dotted_name":
				moduleName = nodeText(child, src)
				// Use the first component as the local alias
				parts := strings.Split(moduleName, ".")
				alias = parts[0]
			default:
				continue
			}
			if moduleName != "" {
				*imports = append(*imports, treesitter.Import{
					Module: moduleName,
					Alias:  alias,
					File:   file,
					Line:   rowToLine(node.StartPosition().Row),
				})
			}
		}
		return

	case "import_from_statement":
		// from flask import Flask, request
		// from . import utils
		// from ..models import User
		moduleNode := node.ChildByFieldName("module_name")
		moduleName := ""
		if moduleNode != nil {
			moduleName = nodeText(moduleNode, src)
		} else {
			// Handle relative imports where module_name field may be absent
			for i := uint(0); i < node.ChildCount(); i++ {
				child := node.Child(i)
				if child != nil && child.Kind() == "relative_import" {
					moduleName = nodeText(child, src)
					break
				}
			}
		}

		// Collect imported symbols.
		// The grammar can produce either:
		//   - an import_list node wrapping the names, OR
		//   - dotted_name/identifier children directly (older grammar versions)
		var syms []string
		seenModule := false
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child == nil {
				continue
			}
			switch child.Kind() {
			case "import_list":
				for j := uint(0); j < child.ChildCount(); j++ {
					grandchild := child.Child(j)
					if grandchild == nil {
						continue
					}
					switch grandchild.Kind() {
					case "dotted_name", "identifier":
						syms = append(syms, nodeText(grandchild, src))
					case "aliased_import":
						nameNode := grandchild.ChildByFieldName("name")
						if nameNode != nil {
							syms = append(syms, nodeText(nameNode, src))
						}
					}
				}
			case "wildcard_import":
				syms = append(syms, "*")
			case "dotted_name":
				// The first dotted_name is the module itself; subsequent ones are imports
				if !seenModule {
					seenModule = true
					// This is the module name - already captured above
				} else {
					syms = append(syms, nodeText(child, src))
				}
			case "aliased_import":
				nameNode := child.ChildByFieldName("name")
				if nameNode != nil {
					syms = append(syms, nodeText(nameNode, src))
				}
			}
		}

		// Normalize module name - strip leading dots for relative imports
		cleanModule := strings.TrimLeft(moduleName, ".")
		if cleanModule == "" && moduleName != "" {
			cleanModule = moduleName
		}

		if cleanModule != "" || len(syms) > 0 {
			*imports = append(*imports, treesitter.Import{
				Module:  cleanModule,
				Symbols: syms,
				File:    file,
				Line:    rowToLine(node.StartPosition().Row),
			})
		}
		return
	}

	// Recurse
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectImports(child, src, file, imports)
	}
}

// ExtractCalls walks the AST to find all call expressions and produces call edges.
// The From field is set to the enclosing function's qualified name (or the module
// if at top level). The To field is the callee's qualified name.
func (e *Extractor) ExtractCalls(file string, src []byte, tree *tree_sitter.Tree, scope *treesitter.Scope) ([]treesitter.Edge, error) {
	root := tree.RootNode()
	mod := moduleFromFile(file)
	var edges []treesitter.Edge
	collectCalls(root, src, file, mod, "", scope, &edges)
	return edges, nil
}

// collectCalls recursively visits nodes to find call expressions.
// currentFunc tracks the enclosing function's qualified ID.
//
//nolint:gocognit,gocyclo // call extraction traverses decorated_definition, function_definition, class_definition, and call nodes
func collectCalls(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, currentFunc string,
	scope *treesitter.Scope,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	switch node.Kind() {
	case "decorated_definition":
		// Find the inner definition node and recurse
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child != nil && (child.Kind() == "function_definition" || child.Kind() == "class_definition") {
				collectCalls(child, src, file, moduleName, currentFunc, scope, edges)
				return
			}
		}
		return

	case "function_definition":
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			name := nodeText(nameNode, src)
			newFunc := moduleName + "." + name
			bodyNode := node.ChildByFieldName("body")
			if bodyNode != nil {
				collectCalls(bodyNode, src, file, moduleName, newFunc, scope, edges)
			}
		}
		return

	case "class_definition":
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			className := nodeText(nameNode, src)
			bodyNode := node.ChildByFieldName("body")
			if bodyNode != nil {
				collectCallsInClass(bodyNode, src, file, moduleName, className, scope, edges)
			}
		}
		return

	case "call":
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			callee := resolveCallee(funcNode, src)
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
		// Also recurse into arguments
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil {
			collectCalls(argsNode, src, file, moduleName, currentFunc, scope, edges)
		}
		return
	}

	// Recurse into all children
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectCalls(child, src, file, moduleName, currentFunc, scope, edges)
	}
}

// collectCallsInClass handles call extraction inside a class body, tracking
// method context for the From field.
func collectCallsInClass(
	node *tree_sitter.Node,
	src []byte,
	file, moduleName, className string,
	scope *treesitter.Scope,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	if node.Kind() == "function_definition" {
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			name := nodeText(nameNode, src)
			methodFunc := moduleName + "." + className + "." + name
			bodyNode := node.ChildByFieldName("body")
			if bodyNode != nil {
				collectCalls(bodyNode, src, file, moduleName, methodFunc, scope, edges)
			}
		}
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectCallsInClass(child, src, file, moduleName, className, scope, edges)
	}
}

// resolveCallee extracts the callee name from a call's function node.
// For "yaml.load", it returns "yaml.load".
// For "print", it returns "print".
func resolveCallee(node *tree_sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}

	switch node.Kind() {
	case "attribute":
		// e.g. yaml.load → object="yaml", attribute="load"
		objNode := node.ChildByFieldName("object")
		attrNode := node.ChildByFieldName("attribute")
		if objNode != nil && attrNode != nil {
			obj := resolveCallee(objNode, src)
			attr := nodeText(attrNode, src)
			if obj != "" {
				return obj + "." + attr
			}
			return attr
		}

	case "identifier":
		return nodeText(node, src)

	case "call":
		// Chained call like foo()()
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil {
			return resolveCallee(funcNode, src)
		}
	}

	return ""
}
