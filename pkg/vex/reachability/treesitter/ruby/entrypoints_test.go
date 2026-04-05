// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package ruby_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	rubyextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/ruby"
)

// TestFindEntryPoints_RailsController verifies that controller methods routed in routes.rb
// are identified as entry points.
func TestFindEntryPoints_RailsController(t *testing.T) {
	source := `
class PagesController < ApplicationController
  def parse
    "hello"
  end

  def index
    "index"
  end
end
`
	routesSource := `
Rails.application.routes.draw do
  get '/parse', to: 'pages#parse'
end
`

	// Parse controller
	tree, src := parseRuby(t, source)
	defer tree.Close()

	// Parse routes
	routesTree, routesSrc := parseRuby(t, routesSource)
	defer routesTree.Close()

	ext := rubyextractor.New()

	// Extract controller symbols
	symbols, err := ext.ExtractSymbols("app/controllers/pages_controller.rb", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// Register routes from routes.rb
	if err := ext.RegisterRoutes(routesSrc, routesTree); err != nil {
		t.Fatalf("RegisterRoutes failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "")

	var foundParse, foundIndex bool
	for _, ep := range eps {
		switch ep {
		case "PagesController::parse":
			foundParse = true
		case "PagesController::index":
			foundIndex = true
		}
	}

	if !foundParse {
		t.Errorf("expected PagesController::parse to be an entry point; got: %v", eps)
	}
	// index is not in routes, so it should NOT be an entry point
	if foundIndex {
		t.Errorf("did not expect PagesController::index to be an entry point")
	}
}

// TestFindEntryPoints_RakeTask verifies that Rake task blocks are entry points.
func TestFindEntryPoints_RakeTask(t *testing.T) {
	source := `
task :build do
  puts "building"
end

task :test => :build do
  puts "testing"
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("Rakefile", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "")

	if len(eps) == 0 {
		t.Error("expected Rake task entry points, got none")
	}

	var foundBuild bool
	for _, ep := range eps {
		if ep == treesitter.SymbolID("task:build") {
			foundBuild = true
		}
	}
	if !foundBuild {
		t.Errorf("expected task:build entry point; got: %v", eps)
	}
}

// TestFindEntryPoints_SinatraRoute verifies that Sinatra route blocks are entry points.
func TestFindEntryPoints_SinatraRoute(t *testing.T) {
	source := `
get '/hello' do
  "Hello World"
end

post '/submit' do
  params[:name]
end
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("app.rb", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "")

	if len(eps) == 0 {
		t.Error("expected Sinatra route entry points, got none")
	}
}

// TestFindEntryPoints_BinScript verifies that methods in bin/ scripts are entry points.
func TestFindEntryPoints_BinScript(t *testing.T) {
	source := `
#!/usr/bin/env ruby
require_relative '../lib/app'

class CLI
  def run(argv)
    App.run(argv)
  end
end

CLI.new.run(ARGV)
`
	tree, src := parseRuby(t, source)
	defer tree.Close()

	ext := rubyextractor.New()
	symbols, err := ext.ExtractSymbols("bin/start", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols failed: %v", err)
	}

	// The source must contain at least one method symbol
	var methodCount int
	for _, sym := range symbols {
		if sym.Kind == treesitter.SymbolMethod {
			methodCount++
		}
	}
	if methodCount < 1 {
		t.Errorf("expected at least one method symbol in bin script, got %d", methodCount)
	}

	eps := ext.FindEntryPoints(symbols, "")

	// All symbols from bin/ files should be entry points
	if len(eps) < 1 {
		t.Errorf("expected at least 1 entry point from bin/ file, got %d; symbols: %v", len(eps), symbols)
	}
}
