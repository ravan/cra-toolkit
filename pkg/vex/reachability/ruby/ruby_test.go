package ruby_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/ruby"
)

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestAnalyzer_Language(t *testing.T) {
	a := ruby.New()
	if lang := a.Language(); lang != "ruby" {
		t.Fatalf("expected 'ruby', got %q", lang)
	}
}

func TestAnalyze_RubyReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "app", "controllers", "pages_controller.rb"), []byte(`
class PagesController < ApplicationController
  def parse
    html = Nokogiri::HTML(params[:content])
    render json: { title: html.css('title').text }
  end
end
`))
	writeFile(t, filepath.Join(dir, "config", "routes.rb"), []byte(`
Rails.application.routes.draw do
  get '/parse', to: 'pages#parse'
end
`))

	analyzer := ruby.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-24836",
		AffectedPURL: "pkg:gem/nokogiri@1.13.3",
		AffectedName: "nokogiri",
		Symbols:      []string{"Nokogiri::HTML"},
		Language:     "ruby",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Reachable {
		t.Errorf("expected Reachable=true, got false; evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one symbol in result")
	}
	if len(result.Paths) == 0 {
		t.Error("expected at least one call path in result")
	}
	if result.Evidence == "" {
		t.Error("expected non-empty evidence")
	}
	t.Logf("Evidence: %s", result.Evidence)
	for i, p := range result.Paths {
		t.Logf("Path %d: %s", i, p)
	}
}

func TestAnalyze_RubyNotReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "app", "controllers", "pages_controller.rb"), []byte(`
class PagesController < ApplicationController
  def index
    render json: { status: 'ok' }
  end
end
`))
	writeFile(t, filepath.Join(dir, "config", "routes.rb"), []byte(`
Rails.application.routes.draw do
  get '/', to: 'pages#index'
end
`))

	analyzer := ruby.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-24836",
		AffectedPURL: "pkg:gem/nokogiri@1.13.3",
		AffectedName: "nokogiri",
		Symbols:      []string{"Nokogiri::HTML"},
		Language:     "ruby",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Errorf("expected Reachable=false, got true; evidence: %s", result.Evidence)
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}

func TestAnalyze_NoSourceFiles(t *testing.T) {
	dir := t.TempDir()

	analyzer := ruby.New()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-24836",
		AffectedPURL: "pkg:gem/nokogiri@1.13.3",
		AffectedName: "nokogiri",
		Symbols:      []string{"Nokogiri::HTML"},
		Language:     "ruby",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false for empty directory")
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
}

func TestIntegration_RubyTreesitterReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "ruby-treesitter-reachable", "source")
	analyzer := ruby.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-24836",
		AffectedPURL: "pkg:gem/nokogiri@1.13.3",
		AffectedName: "nokogiri",
		Symbols:      []string{"Nokogiri::HTML"},
		Language:     "ruby",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if !result.Reachable {
		t.Errorf("expected Reachable=true; evidence: %s", result.Evidence)
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if len(result.Paths) == 0 {
		t.Error("expected at least one call path")
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one reached symbol")
	}

	t.Logf("Evidence: %s", result.Evidence)
	for i, p := range result.Paths {
		t.Logf("Path %d: %s", i, p)
	}
}

func TestIntegration_RubyTreesitterNotReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "ruby-treesitter-not-reachable", "source")
	analyzer := ruby.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-24836",
		AffectedPURL: "pkg:gem/nokogiri@1.13.3",
		AffectedName: "nokogiri",
		Symbols:      []string{"Nokogiri::HTML"},
		Language:     "ruby",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Reachable {
		t.Errorf("expected Reachable=false; evidence: %s", result.Evidence)
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}
