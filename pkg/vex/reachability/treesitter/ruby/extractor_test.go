package ruby_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	rubygrammar "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/grammars/ruby"
	rubyextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/ruby"
)

// parseRuby parses Ruby source and returns the tree and source bytes.
func parseRuby(t *testing.T, source string) (*tree_sitter.Tree, []byte) { //nolint:gocritic // two return values are self-documenting
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	if err := parser.SetLanguage(tree_sitter.NewLanguage(rubygrammar.Language())); err != nil {
		t.Fatalf("set language: %v", err)
	}
	src := []byte(source)
	tree := parser.Parse(src, nil)
	if tree == nil {
		t.Fatal("tree-sitter returned nil tree")
	}
	return tree, src
}

// TestExtractSymbols_InstanceMethod verifies that a Ruby instance method is extracted correctly.
//
//nolint:gocognit,gocyclo // test validates multiple symbol kinds with individual assertions
func TestExtractSymbols_InstanceMethod(t *testing.T) {
	source := `
class PagesController < ApplicationController
  def parse
    "hello"
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("pages_controller.rb", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Expect: class PagesController + method parse = 2 symbols
	if len(symbols) != 2 {
		t.Errorf("expected 2 symbols (class + method), got %d", len(symbols))
		for _, s := range symbols {
			t.Logf("  %s (%s)", s.QualifiedName, s.Kind)
		}
	}

	var foundClass, foundMethod bool
	for _, s := range symbols {
		switch {
		case s.Name == "PagesController" && s.Kind == treesitter.SymbolClass:
			foundClass = true
			if s.ID != "PagesController" {
				t.Errorf("expected ID 'PagesController', got %q", s.ID)
			}
		case s.Name == "parse" && s.Kind == treesitter.SymbolMethod:
			foundMethod = true
			if s.QualifiedName != "PagesController::parse" {
				t.Errorf("expected qualified name 'PagesController::parse', got %q", s.QualifiedName)
			}
			if s.ID != "PagesController::parse" {
				t.Errorf("expected ID 'PagesController::parse', got %q", s.ID)
			}
		}
	}

	if !foundClass {
		t.Error("expected to find class PagesController")
	}
	if !foundMethod {
		t.Error("expected to find method parse")
	}
}

// TestExtractSymbols_SingletonMethod verifies that class-level methods (def self.foo) are extracted.
func TestExtractSymbols_SingletonMethod(t *testing.T) {
	source := `
class MyService
  def self.call(arg)
    arg.upcase
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("my_service.rb", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundSingleton bool
	for _, s := range symbols {
		if s.Name == "call" && s.Kind == treesitter.SymbolMethod {
			foundSingleton = true
			if s.QualifiedName != "MyService::call" {
				t.Errorf("expected 'MyService::call', got %q", s.QualifiedName)
			}
		}
	}
	if !foundSingleton {
		t.Error("expected to find singleton method 'call'")
	}
}

// TestExtractSymbols_Module verifies that module declarations and methods are extracted.
func TestExtractSymbols_Module(t *testing.T) {
	source := `
module Greeter
  def hello
    "hello"
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("greeter.rb", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	var foundModule, foundMethod bool
	for _, s := range symbols {
		switch {
		case s.Name == "Greeter" && s.Kind == treesitter.SymbolModule:
			foundModule = true
		case s.Name == "hello" && s.Kind == treesitter.SymbolMethod:
			foundMethod = true
			if s.QualifiedName != "Greeter::hello" {
				t.Errorf("expected 'Greeter::hello', got %q", s.QualifiedName)
			}
		}
	}
	if !foundModule {
		t.Error("expected to find module Greeter")
	}
	if !foundMethod {
		t.Error("expected to find method hello in module")
	}
}

// TestResolveImports_Require verifies that require and require_relative calls are extracted.
func TestResolveImports_Require(t *testing.T) {
	source := `
require 'nokogiri'
require_relative './utils'
require 'json'
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	imports, err := ext.ResolveImports("app.rb", src, tree, "")
	if err != nil {
		t.Fatalf("ResolveImports failed: %v", err)
	}

	if len(imports) != 3 {
		t.Errorf("expected 3 imports, got %d", len(imports))
		for _, imp := range imports {
			t.Logf("  module=%q alias=%q", imp.Module, imp.Alias)
		}
	}

	modules := make(map[string]bool)
	for _, imp := range imports {
		modules[imp.Module] = true
	}

	for _, expected := range []string{"nokogiri", "./utils", "json"} {
		if !modules[expected] {
			t.Errorf("expected import %q not found", expected)
		}
	}
}

// TestExtractCalls_ScopeResolution verifies that Nokogiri::HTML(args) is captured as a call edge.
func TestExtractCalls_ScopeResolution(t *testing.T) {
	source := `
class PagesController
  def parse
    html = Nokogiri::HTML(params[:content])
    html.css('title').text
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	edges, err := ext.ExtractCalls("pages_controller.rb", src, tree, nil)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundNokogiriHTML bool
	for _, e := range edges {
		if e.To == "Nokogiri::HTML" {
			foundNokogiriHTML = true
			if e.From != "PagesController::parse" {
				t.Errorf("expected From='PagesController::parse', got %q", e.From)
			}
			if e.Kind != treesitter.EdgeDirect {
				t.Errorf("expected EdgeDirect, got %v", e.Kind)
			}
		}
	}

	if !foundNokogiriHTML {
		t.Error("expected call edge to Nokogiri::HTML")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s", e.From, e.To)
		}
	}
}

// TestExtractCalls_MethodCall verifies that regular method calls (obj.method) are captured.
func TestExtractCalls_MethodCall(t *testing.T) {
	source := `
class MyClass
  def run
    client.get('/path')
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	edges, err := ext.ExtractCalls("my_class.rb", src, tree, nil)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var found bool
	for _, e := range edges {
		if string(e.To) == "client::get" {
			found = true
			if e.From != "MyClass::run" {
				t.Errorf("expected From='MyClass::run', got %q", e.From)
			}
		}
	}

	if !found {
		t.Error("expected call edge for client.get('/path')")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s", e.From, e.To)
		}
	}
}

// TestExtractCalls_SendMetaprogramming verifies that send(:method) emits EdgeDispatch.
//
//nolint:gocyclo // test validates two dispatch edges with multiple assertions each
func TestExtractCalls_SendMetaprogramming(t *testing.T) {
	source := `
class Worker
  def process
    send(:do_work)
    public_send(:notify)
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	edges, err := ext.ExtractCalls("worker.rb", src, tree, nil)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundSend, foundPublicSend bool
	for _, e := range edges {
		switch {
		case e.To == "do_work" && e.Kind == treesitter.EdgeDispatch:
			foundSend = true
			if e.Confidence != 0.3 {
				t.Errorf("expected confidence 0.3 for send dispatch, got %f", e.Confidence)
			}
		case e.To == "notify" && e.Kind == treesitter.EdgeDispatch:
			foundPublicSend = true
		}
	}

	if !foundSend {
		t.Error("expected EdgeDispatch for send(:do_work)")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s (%s)", e.From, e.To, e.Kind)
		}
	}
	if !foundPublicSend {
		t.Error("expected EdgeDispatch for public_send(:notify)")
	}
}

// TestExtractCalls_FunctionCall verifies that top-level function calls are captured.
func TestExtractCalls_FunctionCall(t *testing.T) {
	source := `
class MyClass
  def render_page
    render json: { status: 'ok' }
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	edges, err := ext.ExtractCalls("my_class.rb", src, tree, nil)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundRender bool
	for _, e := range edges {
		if e.To == "render" {
			foundRender = true
			if e.From != "MyClass::render_page" {
				t.Errorf("expected From='MyClass::render_page', got %q", e.From)
			}
		}
	}

	if !foundRender {
		t.Error("expected call edge to render")
	}
}

// TestExtractCalls_CommandCall verifies that command-style calls without parentheses
// (e.g. render json: {...}, raise ArgumentError, "msg") are captured as call edges.
func TestExtractCalls_CommandCall(t *testing.T) {
	source := `
class ApplicationController
  def show
    render json: { status: 'ok' }
    raise ArgumentError, "invalid input"
  end
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	edges, err := ext.ExtractCalls("application_controller.rb", src, tree, nil)
	if err != nil {
		t.Fatalf("ExtractCalls failed: %v", err)
	}

	var foundRender bool
	for _, e := range edges {
		if e.To == "render" {
			foundRender = true
			if e.From != "ApplicationController::show" {
				t.Errorf("expected From='ApplicationController::show', got %q", e.From)
			}
		}
	}

	if !foundRender {
		t.Error("expected call edge to render (command_call without parentheses)")
		for _, e := range edges {
			t.Logf("  edge: %s -> %s", e.From, e.To)
		}
	}
}
