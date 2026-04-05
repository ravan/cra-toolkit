// Package java implements tree-sitter AST extraction for Java source files.
// It extracts symbols (classes, methods, constructors), imports, and call edges.
// Class Hierarchy Analysis (CHA) is performed to resolve interface dispatch.
package java

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// Compile-time interface conformance check.
// If the Extractor methods diverge from the LanguageExtractor interface,
// this line will produce a compile error pointing directly at the mismatch.
var _ treesitter.LanguageExtractor = (*Extractor)(nil)

// Extractor extracts symbols, imports, and call edges from Java ASTs.
// It also builds a CHA (Class Hierarchy Analysis) table for interface dispatch resolution.
type Extractor struct {
	// annotations maps SymbolID → annotation strings found on the definition.
	annotations map[treesitter.SymbolID][]string

	// publicStaticMethods is the set of SymbolIDs for methods declared with both
	// "public" and "static" modifiers. Used to enforce the Java main entry point contract.
	publicStaticMethods map[treesitter.SymbolID]bool

	// cha maps interface/abstract-class simple name → slice of concrete implementor class names.
	// Both keys and values are simple (unqualified) class names.
	// E.g. "Handler" → ["LogHandler", "FileHandler"]
	cha map[string][]string

	// methodOwner maps simple method name → owning class simple name.
	// Used to resolve interface method calls to concrete implementor methods.
	// E.g. "handle" → ["LogHandler", "FileHandler"] (all classes that define "handle")
	methodToClasses map[string][]string

	// paramTypes maps (classSimpleName, methodSimpleName, paramName) → paramType simple name.
	// Used for CHA: when a method takes a parameter of interface type, we can infer dispatch.
	// E.g. ("App", "run", "handler") → "Handler"
	paramTypes map[paramKey]string

	// classPackage maps class simple name → package name.
	classPackage map[string]string
}

// paramKey identifies a single parameter for CHA parameter type tracking.
type paramKey struct {
	class, method, param string
}

// New creates a new Java Extractor.
func New() *Extractor {
	return &Extractor{
		annotations:         make(map[treesitter.SymbolID][]string),
		publicStaticMethods: make(map[treesitter.SymbolID]bool),
		cha:                 make(map[string][]string),
		methodToClasses:     make(map[string][]string),
		paramTypes:          make(map[paramKey]string),
		classPackage:        make(map[string]string),
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

// packageFromAST extracts the package name from the root of a Java AST.
// Returns empty string if no package_declaration is found.
//
//nolint:gocognit // nested AST traversal for package_declaration requires multiple branches
func packageFromAST(root *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() == "package_declaration" {
			// package_declaration: "package" scoped_identifier/identifier ";"
			for j := uint(0); j < child.ChildCount(); j++ {
				grandchild := child.Child(j)
				if grandchild == nil {
					continue
				}
				k := grandchild.Kind()
				if k == "scoped_identifier" || k == "identifier" {
					return nodeText(grandchild, src)
				}
			}
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtractSymbols
// ─────────────────────────────────────────────────────────────────────────────

// ExtractSymbols walks the AST to find all class and method definitions.
// Methods inside classes are annotated with SymbolMethod and a qualified name.
// It also builds the CHA table (interface→implementors) and paramType map.
func (e *Extractor) ExtractSymbols(file string, src []byte, tree *tree_sitter.Tree) ([]*treesitter.Symbol, error) {
	// Reset per-call state
	e.annotations = make(map[treesitter.SymbolID][]string)
	e.publicStaticMethods = make(map[treesitter.SymbolID]bool)
	e.cha = make(map[string][]string)
	e.methodToClasses = make(map[string][]string)
	e.paramTypes = make(map[paramKey]string)
	e.classPackage = make(map[string]string)

	root := tree.RootNode()
	pkg := packageFromAST(root, src)

	var symbols []*treesitter.Symbol
	walkSymbols(root, src, file, pkg, "", &symbols, e.annotations, e.publicStaticMethods, e.cha, e.methodToClasses, e.paramTypes, e.classPackage)
	return symbols, nil
}

// walkSymbols recursively visits AST nodes to collect class and method definitions.
//
//nolint:gocognit,gocyclo // AST walker handles class, interface, method, constructor nodes
func walkSymbols(
	node *tree_sitter.Node,
	src []byte,
	file, pkg, currentClass string,
	symbols *[]*treesitter.Symbol,
	annotations map[treesitter.SymbolID][]string,
	publicStaticMethods map[treesitter.SymbolID]bool,
	cha map[string][]string,
	methodToClasses map[string][]string,
	paramTypes map[paramKey]string,
	classPackage map[string]string,
) {
	if node == nil {
		return
	}

	kind := node.Kind()

	switch kind {
	case "class_declaration", "interface_declaration", "enum_declaration":
		extractClassNode(node, src, file, pkg, currentClass, symbols, annotations, publicStaticMethods, cha, methodToClasses, paramTypes, classPackage)
		return

	case "method_declaration", "constructor_declaration":
		// Top-level methods (rare in Java but handle gracefully)
		extractMethodNode(node, src, file, pkg, currentClass, symbols, annotations, publicStaticMethods, methodToClasses, paramTypes)
		return
	}

	// Recurse into children for all other node types
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		walkSymbols(child, src, file, pkg, currentClass, symbols, annotations, publicStaticMethods, cha, methodToClasses, paramTypes, classPackage)
	}
}

// extractClassNode processes a class_declaration, interface_declaration, or enum_declaration.
//
//nolint:gocognit,gocyclo // processes class hierarchy info and recurses into class body
func extractClassNode(
	node *tree_sitter.Node,
	src []byte,
	file, pkg, outerClass string,
	symbols *[]*treesitter.Symbol,
	annotations map[treesitter.SymbolID][]string,
	publicStaticMethods map[treesitter.SymbolID]bool,
	cha map[string][]string,
	methodToClasses map[string][]string,
	paramTypes map[paramKey]string,
	classPackage map[string]string,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	className := nodeText(nameNode, src)

	// Build qualified name
	qualifiedName := qualifyClass(pkg, outerClass, className)
	id := treesitter.SymbolID(qualifiedName)

	// Record package for this class (for CHA resolution)
	classPackage[className] = pkg

	// Collect annotations on this class
	var classAnns []string
	collectAnnotations(node, src, &classAnns)
	if len(classAnns) > 0 {
		annotations[id] = classAnns
	}

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          className,
		QualifiedName: qualifiedName,
		Language:      "java",
		File:          file,
		Package:       pkg,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolClass,
	}
	*symbols = append(*symbols, sym)

	// Build CHA: record implements/extends relationships
	// interfaces field: for "implements Handler, Runnable"
	interfacesNode := node.ChildByFieldName("interfaces")
	if interfacesNode != nil {
		collectImplements(interfacesNode, src, className, cha)
	}
	// superclass field: for "extends AbstractBase"
	superNode := node.ChildByFieldName("superclass")
	if superNode != nil {
		superName := extractSimpleTypeName(superNode, src)
		if superName != "" {
			cha[superName] = appendUnique(cha[superName], className)
		}
	}

	// Recurse into class body
	bodyNode := node.ChildByFieldName("body")
	if bodyNode == nil {
		return
	}
	for i := uint(0); i < bodyNode.ChildCount(); i++ {
		child := bodyNode.Child(i)
		if child == nil {
			continue
		}
		childKind := child.Kind()
		switch childKind {
		case "method_declaration", "constructor_declaration":
			extractMethodNode(child, src, file, pkg, className, symbols, annotations, publicStaticMethods, methodToClasses, paramTypes)
		case "class_declaration", "interface_declaration", "enum_declaration":
			// Inner class
			extractClassNode(child, src, file, pkg, qualifiedClass(outerClass, className), symbols, annotations, publicStaticMethods, cha, methodToClasses, paramTypes, classPackage)
		}
	}
}

// extractMethodNode processes a method_declaration or constructor_declaration.
func extractMethodNode(
	node *tree_sitter.Node,
	src []byte,
	file, pkg, className string,
	symbols *[]*treesitter.Symbol,
	annotations map[treesitter.SymbolID][]string,
	publicStaticMethods map[treesitter.SymbolID]bool,
	methodToClasses map[string][]string,
	paramTypes map[paramKey]string,
) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	methodName := nodeText(nameNode, src)

	// Build qualified name: pkg.ClassName.methodName
	qualifiedName := qualifyMethod(pkg, className, methodName)
	id := treesitter.SymbolID(qualifiedName)

	// Collect annotations on this method
	var anns []string
	collectAnnotations(node, src, &anns)
	if len(anns) > 0 {
		annotations[id] = anns
	}

	// Track whether this method has both "public" and "static" modifiers.
	// Required for the Java main entry point contract: public static void main(String[] args).
	if hasPublicStaticModifiers(node, src) {
		publicStaticMethods[id] = true
	}

	sym := &treesitter.Symbol{
		ID:            id,
		Name:          methodName,
		QualifiedName: qualifiedName,
		Language:      "java",
		File:          file,
		Package:       pkg,
		StartLine:     rowToLine(node.StartPosition().Row),
		EndLine:       rowToLine(node.EndPosition().Row),
		Kind:          treesitter.SymbolMethod,
	}
	*symbols = append(*symbols, sym)

	// Register method→class mapping for CHA
	if className != "" {
		methodToClasses[methodName] = appendUnique(methodToClasses[methodName], className)
	}

	// Collect parameter types for CHA
	paramsNode := node.ChildByFieldName("parameters")
	if paramsNode != nil && className != "" {
		collectParamTypes(paramsNode, src, className, methodName, paramTypes)
	}
}

// collectParamTypes extracts parameter names and their declared types from a formal_parameters node.
func collectParamTypes(
	paramsNode *tree_sitter.Node,
	src []byte,
	className, methodName string,
	paramTypes map[paramKey]string,
) {
	for i := uint(0); i < paramsNode.ChildCount(); i++ {
		child := paramsNode.Child(i)
		if child == nil {
			continue
		}
		if child.Kind() != "formal_parameter" {
			continue
		}
		typeNode := child.ChildByFieldName("type")
		nameNode := child.ChildByFieldName("name")
		if typeNode == nil || nameNode == nil {
			continue
		}
		typeName := extractSimpleTypeName(typeNode, src)
		paramName := nodeText(nameNode, src)
		if typeName != "" && paramName != "" {
			key := paramKey{class: className, method: methodName, param: paramName}
			paramTypes[key] = typeName
		}
	}
}

// hasPublicStaticModifiers returns true if the node's modifiers child contains
// both "public" and "static" keywords. Used to enforce the Java main entry point contract.
func hasPublicStaticModifiers(node *tree_sitter.Node, src []byte) bool {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil || child.Kind() != "modifiers" {
			continue
		}
		var hasPublic, hasStatic bool
		for j := uint(0); j < child.ChildCount(); j++ {
			grandchild := child.Child(j)
			if grandchild == nil {
				continue
			}
			switch nodeText(grandchild, src) {
			case "public":
				hasPublic = true
			case "static":
				hasStatic = true
			}
		}
		return hasPublic && hasStatic
	}
	return false
}

// collectAnnotations scans an AST node's children for annotation/marker_annotation nodes.
// In Java's grammar, annotations appear inside a "modifiers" child node.
// E.g. method_declaration → modifiers → [marker_annotation | annotation, "public", ...]
//
//nolint:gocognit // two-level modifiers scan requires nested branching
func collectAnnotations(node *tree_sitter.Node, src []byte, anns *[]string) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		k := child.Kind()
		switch k {
		case "annotation", "marker_annotation":
			// Direct annotation child (rare but handle gracefully)
			*anns = append(*anns, "@"+annotationName(child, src))
		case "modifiers":
			// The common case: annotations are inside a modifiers node
			for j := uint(0); j < child.ChildCount(); j++ {
				grandchild := child.Child(j)
				if grandchild == nil {
					continue
				}
				gk := grandchild.Kind()
				if gk == "annotation" || gk == "marker_annotation" {
					*anns = append(*anns, "@"+annotationName(grandchild, src))
				}
			}
		}
	}
}

// annotationName returns the annotation name (without the @).
func annotationName(node *tree_sitter.Node, src []byte) string {
	// annotation: "@" "name" "(" arguments ")"
	// marker_annotation: "@" "name"
	nameNode := node.ChildByFieldName("name")
	if nameNode != nil {
		return nodeText(nameNode, src)
	}
	// Fallback: strip leading "@" from full text
	text := nodeText(node, src)
	if idx := strings.Index(text, "("); idx > 0 {
		text = text[:idx]
	}
	return strings.TrimPrefix(text, "@")
}

// collectImplements scans an interfaces node (from "implements X, Y") and adds
// className as an implementor of each interface in the cha map.
//
//nolint:gocognit // handles both type_list wrapper and direct type children across grammar versions
func collectImplements(interfacesNode *tree_sitter.Node, src []byte, className string, cha map[string][]string) {
	for i := uint(0); i < interfacesNode.ChildCount(); i++ {
		child := interfacesNode.Child(i)
		if child == nil {
			continue
		}
		// The grammar uses "type_list" inside the interfaces node
		if child.Kind() == "type_list" {
			for j := uint(0); j < child.ChildCount(); j++ {
				typeNode := child.Child(j)
				if typeNode == nil {
					continue
				}
				iface := extractSimpleTypeName(typeNode, src)
				if iface != "" {
					cha[iface] = appendUnique(cha[iface], className)
				}
			}
		} else {
			// Some grammar versions place types directly
			iface := extractSimpleTypeName(child, src)
			if iface != "" {
				cha[iface] = appendUnique(cha[iface], className)
			}
		}
	}
}

// extractSimpleTypeName returns the simple (unqualified) class name from a type node.
func extractSimpleTypeName(node *tree_sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	text := nodeText(node, src)
	// Handle generic types: "List<String>" → "List"
	if idx := strings.IndexByte(text, '<'); idx > 0 {
		text = text[:idx]
	}
	// Handle qualified types: "java.util.List" → "List"
	if idx := strings.LastIndexByte(text, '.'); idx >= 0 {
		text = text[idx+1:]
	}
	return strings.TrimSpace(text)
}

// qualifyClass builds a qualified class name: "pkg.OuterClass.ClassName" or "pkg.ClassName".
func qualifyClass(pkg, outerClass, className string) string {
	parts := []string{}
	if pkg != "" {
		parts = append(parts, pkg)
	}
	if outerClass != "" {
		parts = append(parts, outerClass)
	}
	parts = append(parts, className)
	return strings.Join(parts, ".")
}

// qualifyMethod builds a qualified method name: "pkg.ClassName.methodName".
func qualifyMethod(pkg, className, methodName string) string {
	parts := []string{}
	if pkg != "" {
		parts = append(parts, pkg)
	}
	if className != "" {
		parts = append(parts, className)
	}
	parts = append(parts, methodName)
	return strings.Join(parts, ".")
}

// qualifiedClass builds "OuterClass.InnerClass" for inner class tracking.
func qualifiedClass(outerClass, className string) string {
	if outerClass == "" {
		return className
	}
	return outerClass + "." + className
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

// ─────────────────────────────────────────────────────────────────────────────
// ResolveImports
// ─────────────────────────────────────────────────────────────────────────────

// ResolveImports walks the AST to find all import declarations.
// Java imports are fully qualified: "import org.apache.logging.log4j.Logger;"
// The simple class name (last segment) is used as the alias.
func (e *Extractor) ResolveImports(file string, src []byte, tree *tree_sitter.Tree, _ string) ([]treesitter.Import, error) {
	root := tree.RootNode()
	var imports []treesitter.Import
	collectImports(root, src, file, &imports)
	return imports, nil
}

// collectImports recursively finds import_declaration nodes.
func collectImports(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	if node == nil {
		return
	}

	if node.Kind() == "import_declaration" {
		extractImportDecl(node, src, file, imports)
		return
	}

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectImports(child, src, file, imports)
	}
}

// extractImportDecl processes a single import_declaration node.
// import_declaration: "import" ["static"] scoped_identifier ";"
func extractImportDecl(node *tree_sitter.Node, src []byte, file string, imports *[]treesitter.Import) {
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		k := child.Kind()
		if k == "scoped_identifier" || k == "identifier" {
			fqn := nodeText(child, src)
			if fqn == "" {
				continue
			}
			// Simple name = last segment (used as alias)
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

// ExtractCalls walks the AST to find all method invocations and produces call edges.
// For direct calls (foo.bar()), EdgeDirect edges are emitted.
// For CHA dispatch (calls through interface-typed parameters), EdgeDispatch edges
// with confidence 0.5 are emitted to all known implementors.
func (e *Extractor) ExtractCalls(file string, src []byte, tree *tree_sitter.Tree, _ *treesitter.Scope) ([]treesitter.Edge, error) {
	root := tree.RootNode()
	pkg := packageFromAST(root, src)

	var edges []treesitter.Edge
	collectCalls(root, src, file, pkg, "", "", e.cha, e.methodToClasses, e.paramTypes, e.classPackage, &edges)
	return edges, nil
}

// callContext holds the walking state for call extraction.
type callContext struct {
	file            string
	pkg             string
	currentClass    string
	currentMethod   string
	cha             map[string][]string
	methodToClasses map[string][]string
	paramTypes      map[paramKey]string
	classPackage    map[string]string
	edges           *[]treesitter.Edge
}

// collectCalls recursively visits nodes to find method invocations.
//
//nolint:gocognit,gocyclo // call extraction handles class body, method body, and invocation nodes
func collectCalls(
	node *tree_sitter.Node,
	src []byte,
	file, pkg, currentClass, currentMethod string,
	cha map[string][]string,
	methodToClasses map[string][]string,
	paramTypes map[paramKey]string,
	classPackage map[string]string,
	edges *[]treesitter.Edge,
) {
	if node == nil {
		return
	}

	kind := node.Kind()

	switch kind {
	case "class_declaration", "interface_declaration", "enum_declaration":
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		className := nodeText(nameNode, src)
		bodyNode := node.ChildByFieldName("body")
		if bodyNode != nil {
			for i := uint(0); i < bodyNode.ChildCount(); i++ {
				child := bodyNode.Child(i)
				collectCalls(child, src, file, pkg, className, currentMethod, cha, methodToClasses, paramTypes, classPackage, edges)
			}
		}
		return

	case "method_declaration", "constructor_declaration":
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		methodName := nodeText(nameNode, src)
		bodyNode := node.ChildByFieldName("body")
		if bodyNode != nil {
			collectCalls(bodyNode, src, file, pkg, currentClass, methodName, cha, methodToClasses, paramTypes, classPackage, edges)
		}
		return

	case "method_invocation":
		ctx := &callContext{
			file:            file,
			pkg:             pkg,
			currentClass:    currentClass,
			currentMethod:   currentMethod,
			cha:             cha,
			methodToClasses: methodToClasses,
			paramTypes:      paramTypes,
			classPackage:    classPackage,
			edges:           edges,
		}
		processMethodInvocation(node, src, ctx)
		// Recurse into arguments for nested calls
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil {
			for i := uint(0); i < argsNode.ChildCount(); i++ {
				child := argsNode.Child(i)
				collectCalls(child, src, file, pkg, currentClass, currentMethod, cha, methodToClasses, paramTypes, classPackage, edges)
			}
		}
		return

	case "object_creation_expression":
		ctx := &callContext{
			file:            file,
			pkg:             pkg,
			currentClass:    currentClass,
			currentMethod:   currentMethod,
			cha:             cha,
			methodToClasses: methodToClasses,
			paramTypes:      paramTypes,
			classPackage:    classPackage,
			edges:           edges,
		}
		processObjectCreation(node, src, ctx)
		argsNode := node.ChildByFieldName("arguments")
		if argsNode != nil {
			for i := uint(0); i < argsNode.ChildCount(); i++ {
				child := argsNode.Child(i)
				collectCalls(child, src, file, pkg, currentClass, currentMethod, cha, methodToClasses, paramTypes, classPackage, edges)
			}
		}
		return
	}

	// Recurse into all children
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		collectCalls(child, src, file, pkg, currentClass, currentMethod, cha, methodToClasses, paramTypes, classPackage, edges)
	}
}

// processMethodInvocation handles a method_invocation node and emits call edges.
//
//nolint:gocognit,gocyclo // CHA dispatch and direct call path require multiple branches
func processMethodInvocation(node *tree_sitter.Node, src []byte, ctx *callContext) {
	methodNameNode := node.ChildByFieldName("name")
	if methodNameNode == nil {
		return
	}
	methodName := nodeText(methodNameNode, src)

	objectNode := node.ChildByFieldName("object")

	// Build the from SymbolID
	from := ctx.buildFrom()

	// Try CHA dispatch: check if objectNode is a parameter with interface type
	if objectNode != nil && ctx.currentClass != "" && ctx.currentMethod != "" {
		objectName := nodeText(objectNode, src)
		key := paramKey{class: ctx.currentClass, method: ctx.currentMethod, param: objectName}
		if paramType, ok := ctx.paramTypes[key]; ok {
			// paramType is an interface/abstract class — emit dispatch edges to all implementors
			if implementors, ok := ctx.cha[paramType]; ok && len(implementors) > 0 {
				for _, impl := range implementors {
					implPkg := ctx.classPackage[impl]
					to := treesitter.SymbolID(qualifyMethod(implPkg, impl, methodName))
					*ctx.edges = append(*ctx.edges, treesitter.Edge{
						From:       from,
						To:         to,
						Kind:       treesitter.EdgeDispatch,
						Confidence: 0.5,
						File:       ctx.file,
						Line:       rowToLine(node.StartPosition().Row),
					})
				}
				return
			}
		}
	}

	// Direct call
	var calleeStr string
	if objectNode != nil {
		objectText := resolveObjectName(objectNode, src)
		if objectText != "" {
			calleeStr = objectText + "." + methodName
		} else {
			calleeStr = methodName
		}
	} else {
		// Unqualified call within same class
		if ctx.currentClass != "" {
			calleeStr = qualifyMethod(ctx.pkg, ctx.currentClass, methodName)
		} else {
			calleeStr = methodName
		}
	}

	if calleeStr == "" {
		return
	}

	*ctx.edges = append(*ctx.edges, treesitter.Edge{
		From:       from,
		To:         treesitter.SymbolID(calleeStr),
		Kind:       treesitter.EdgeDirect,
		Confidence: 1.0,
		File:       ctx.file,
		Line:       rowToLine(node.StartPosition().Row),
	})
}

// processObjectCreation handles an object_creation_expression (new Foo(...)).
func processObjectCreation(node *tree_sitter.Node, src []byte, ctx *callContext) {
	typeNode := node.ChildByFieldName("type")
	if typeNode == nil {
		return
	}
	typeName := extractSimpleTypeName(typeNode, src)
	if typeName == "" {
		return
	}

	from := ctx.buildFrom()
	// Treat "new Foo()" as a call to "Foo.<init>" (constructor pattern)
	typePkg := ctx.classPackage[typeName]
	to := treesitter.SymbolID(qualifyMethod(typePkg, typeName, "<init>"))

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
func (ctx *callContext) buildFrom() treesitter.SymbolID {
	if ctx.currentClass != "" && ctx.currentMethod != "" {
		return treesitter.SymbolID(qualifyMethod(ctx.pkg, ctx.currentClass, ctx.currentMethod))
	}
	if ctx.currentClass != "" {
		return treesitter.SymbolID(qualifyClass(ctx.pkg, "", ctx.currentClass))
	}
	return treesitter.SymbolID(ctx.pkg)
}

// resolveObjectName returns the text for an object node in a method invocation.
// For "System.out.println", the object is "System.out".
func resolveObjectName(node *tree_sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	return nodeText(node, src)
}
