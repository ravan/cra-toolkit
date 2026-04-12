// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby_test

import (
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter"
	rubygrammar "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/grammars/ruby"
	rubyextractor "github.com/ravan/cra-toolkit/pkg/vex/reachability/treesitter/ruby"
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

func TestExtractSymbols_NestedModule(t *testing.T) {
	source := `module Admin
  class UsersController
    def create
      "ok"
    end
  end
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("app.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	wantIDs := map[string]bool{
		"Admin":                          true,
		"Admin::UsersController":         true,
		"Admin::UsersController::create": true,
	}
	gotIDs := make(map[string]bool)
	for _, s := range symbols {
		gotIDs[string(s.ID)] = true
	}
	for id := range wantIDs {
		if !gotIDs[id] {
			t.Errorf("missing symbol %q; got %v", id, symbolKeys(gotIDs))
		}
	}
}

//nolint:dupl // similar search structure is intentional — different fixture, different target symbol
func TestExtractSymbols_DeeplyNested(t *testing.T) {
	source := `module A
  module B
    class C
      def d
        "deep"
      end
    end
  end
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("deep.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, s := range symbols {
		if string(s.ID) == "A::B::C::d" {
			found = true
			break
		}
	}
	if !found {
		var ids []string
		for _, s := range symbols {
			ids = append(ids, string(s.ID))
		}
		t.Errorf("expected A::B::C::d, got %v", ids)
	}
}

//nolint:dupl // similar search structure is intentional — different fixture, different target symbol
func TestExtractSymbols_CompoundClassName(t *testing.T) {
	source := `class Admin::UsersController
  def index
    "ok"
  end
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("app.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, s := range symbols {
		if string(s.ID) == "Admin::UsersController::index" {
			found = true
			break
		}
	}
	if !found {
		var ids []string
		for _, s := range symbols {
			ids = append(ids, string(s.ID))
		}
		t.Errorf("expected Admin::UsersController::index, got %v", ids)
	}
}

func symbolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestExtractSymbols_IncludeModule(t *testing.T) {
	source := `class Foo
  include Cacheable
  include Admin::Helpers
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	_, err := ext.ExtractSymbols("foo.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	mixins := ext.State().Mixins["Foo"]
	if len(mixins) != 2 {
		t.Fatalf("expected 2 mixins for Foo, got %d: %+v", len(mixins), mixins)
	}
	if mixins[0].Module != "Cacheable" || mixins[0].Kind != "include" {
		t.Errorf("mixin[0] = %+v, want {Cacheable, include}", mixins[0])
	}
	if mixins[1].Module != "Admin::Helpers" || mixins[1].Kind != "include" {
		t.Errorf("mixin[1] = %+v, want {Admin::Helpers, include}", mixins[1])
	}
}

func TestExtractSymbols_ExtendAndPrepend(t *testing.T) {
	source := `class Bar
  extend ClassMethods
  prepend Auditable
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	_, err := ext.ExtractSymbols("bar.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	mixins := ext.State().Mixins["Bar"]
	if len(mixins) != 2 {
		t.Fatalf("expected 2 mixins for Bar, got %d", len(mixins))
	}
	kinds := make(map[string]bool)
	for _, m := range mixins {
		kinds[m.Kind] = true
	}
	if !kinds["extend"] {
		t.Error("missing extend mixin")
	}
	if !kinds["prepend"] {
		t.Error("missing prepend mixin")
	}
}

func TestExtractSymbols_ClassHierarchy(t *testing.T) {
	source := `class Child < Base
  def hello
    "hi"
  end
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	_, err := ext.ExtractSymbols("child.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	parent, ok := ext.State().Hierarchy["Child"]
	if !ok || parent != "Base" {
		t.Errorf("Hierarchy[Child] = %q, want %q", parent, "Base")
	}
}

func TestExtractSymbols_ModuleMethods(t *testing.T) {
	source := `module Cacheable
  def cache_key
    "key"
  end

  def expire_cache
    "expired"
  end
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	_, err := ext.ExtractSymbols("cacheable.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	methods := ext.State().ModuleMethods["Cacheable"]
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods for Cacheable, got %d: %v", len(methods), methods)
	}
}

func TestExtractSymbols_AttrAccessor(t *testing.T) {
	source := `class Config
  attr_accessor :host, :port
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("config.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	wantMethods := map[string]bool{
		"Config::host":  true,
		"Config::host=": true,
		"Config::port":  true,
		"Config::port=": true,
	}
	for _, s := range symbols {
		delete(wantMethods, string(s.ID))
	}
	for missing := range wantMethods {
		t.Errorf("missing synthesized method %q", missing)
	}
}

func TestExtractSymbols_AttrReader(t *testing.T) {
	source := `class User
  attr_reader :id
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("user.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	foundGetter := false
	foundSetter := false
	for _, s := range symbols {
		if string(s.ID) == "User::id" {
			foundGetter = true
		}
		if string(s.ID) == "User::id=" {
			foundSetter = true
		}
	}
	if !foundGetter {
		t.Error("missing getter User::id")
	}
	if foundSetter {
		t.Error("attr_reader should not generate setter User::id=")
	}
}

func TestExtractSymbols_AttrWriter(t *testing.T) {
	source := `class User
  attr_writer :password
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("user.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	foundGetter := false
	foundSetter := false
	for _, s := range symbols {
		if string(s.ID) == "User::password" {
			foundGetter = true
		}
		if string(s.ID) == "User::password=" {
			foundSetter = true
		}
	}
	if foundGetter {
		t.Error("attr_writer should not generate getter User::password")
	}
	if !foundSetter {
		t.Error("missing setter User::password=")
	}
}

func TestExtractSymbols_AttrWithPrivate(t *testing.T) {
	source := `class Foo
  attr_accessor :public_name

  private

  attr_accessor :secret_name
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("foo.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "public_name":
			if !s.IsPublic {
				t.Errorf("public_name should have IsPublic=true")
			}
		case "secret_name":
			if s.IsPublic {
				t.Errorf("secret_name should have IsPublic=false (after private)")
			}
		}
	}
}

func TestExtractSymbols_PrivateMethod(t *testing.T) {
	source := `class Foo
  def public_method
    "hi"
  end

  private

  def private_method
    "secret"
  end
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("foo.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "public_method":
			if !s.IsPublic {
				t.Errorf("public_method should have IsPublic=true")
			}
		case "private_method":
			if s.IsPublic {
				t.Errorf("private_method should have IsPublic=false")
			}
		}
	}
}

func TestExtractSymbols_ProtectedMethod(t *testing.T) {
	source := `class Foo
  def open_method
    "open"
  end

  protected

  def guarded_method
    "guarded"
  end
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("foo.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "open_method":
			if !s.IsPublic {
				t.Errorf("open_method should have IsPublic=true")
			}
		case "guarded_method":
			if s.IsPublic {
				t.Errorf("guarded_method should have IsPublic=false")
			}
		}
	}
}

func TestExtractSymbols_ExplicitPrivate(t *testing.T) {
	source := `class Foo
  def alpha
    "a"
  end

  def beta
    "b"
  end

  private :beta
end`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("foo.rb", src, tree)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range symbols {
		switch s.Name {
		case "alpha":
			if !s.IsPublic {
				t.Errorf("alpha should have IsPublic=true")
			}
		case "beta":
			if s.IsPublic {
				t.Errorf("beta should have IsPublic=false after private :beta")
			}
		}
	}
}
