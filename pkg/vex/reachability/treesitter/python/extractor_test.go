package python_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/python"
	pyextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/python"
)

func parseSource(t *testing.T, source string) (*tree_sitter.Tree, []byte) {
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(python.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

func TestExtractSymbols_Functions(t *testing.T) {
	source := `def hello():
    pass

def process(data):
    return data.strip()

class Handler:
    def handle(self, request):
        return self.process(request)

    def process(self, data):
        return data
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	symbols, err := ext.ExtractSymbols("app.py", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Should find: hello, process, Handler, Handler.handle, Handler.process
	if len(symbols) < 5 {
		t.Errorf("expected at least 5 symbols, got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s) at line %d", s.QualifiedName, s.Kind, s.StartLine)
		}
	}

	var foundHello bool
	for _, s := range symbols {
		if s.Name == "hello" && s.Kind == treesitter.SymbolFunction {
			foundHello = true
		}
	}
	if !foundHello {
		t.Error("expected to find function 'hello'")
	}

	var foundHandler bool
	for _, s := range symbols {
		if s.Name == "Handler" && s.Kind == treesitter.SymbolClass {
			foundHandler = true
		}
	}
	if !foundHandler {
		t.Error("expected to find class 'Handler'")
	}

	var foundMethod bool
	for _, s := range symbols {
		if s.Name == "handle" && s.Kind == treesitter.SymbolMethod {
			foundMethod = true
		}
	}
	if !foundMethod {
		t.Error("expected to find method 'handle'")
	}
}

func TestResolveImports_Python(t *testing.T) {
	source := `import yaml
import os.path
from flask import Flask, request
from . import utils
from ..models import User
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	imports, err := ext.ResolveImports("app.py", src, tree, "/project")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) < 4 {
		t.Errorf("expected at least 4 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  %s (symbols: %v, alias: %q)", imp.Module, imp.Symbols, imp.Alias)
		}
	}

	var foundYaml bool
	for _, imp := range imports {
		if imp.Module == "yaml" && len(imp.Symbols) == 0 {
			foundYaml = true
		}
	}
	if !foundYaml {
		t.Error("expected to find 'import yaml'")
	}

	var foundFlask bool
	for _, imp := range imports {
		if imp.Module == "flask" {
			foundFlask = true
			if len(imp.Symbols) != 2 {
				t.Errorf("expected 2 symbols from flask import, got %d", len(imp.Symbols))
			}
		}
	}
	if !foundFlask {
		t.Error("expected to find 'from flask import Flask, request'")
	}
}

func TestExtractCalls_Python(t *testing.T) {
	source := `import yaml

def process():
    data = yaml.load("key: value")
    result = yaml.safe_load(data)
    print(result)
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := pyextractor.New()
	scope := treesitter.NewScope(nil)
	scope.DefineImport("yaml", "yaml", []string{})

	edges, err := ext.ExtractCalls("app.py", src, tree, scope)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	// Should find calls: yaml.load, yaml.safe_load, print
	if len(edges) < 3 {
		t.Errorf("expected at least 3 call edges, got %d", len(edges))
		for _, e := range edges {
			t.Logf("  %s -> %s (%s)", e.From, e.To, e.Kind)
		}
	}

	var foundYamlLoad bool
	for _, e := range edges {
		if e.To == "yaml.load" {
			foundYamlLoad = true
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("expected EdgeDirect for yaml.load call, got %s", e.Kind)
			}
		}
	}
	if !foundYamlLoad {
		t.Error("expected to find call to yaml.load")
	}
}
