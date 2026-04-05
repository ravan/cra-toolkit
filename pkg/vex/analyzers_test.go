package vex

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAnalyzers_TreesitterFallback(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("PyYAML==5.3"), 0o644) //nolint:errcheck // test helper

	analyzers := buildAnalyzers(dir)

	if _, ok := analyzers["python"]; !ok {
		t.Error("expected python analyzer to be registered")
	}
	if _, ok := analyzers["generic"]; !ok {
		t.Error("expected generic fallback analyzer")
	}
}

func TestBuildAnalyzers_AllLanguages(t *testing.T) {
	dir := t.TempDir()

	// Create markers for all supported languages.
	markers := []string{
		"go.mod",
		"Cargo.toml",
		"package.json",
		"requirements.txt",
		"pom.xml",
		"composer.json",
		"Gemfile",
		"App.csproj",
	}
	for _, m := range markers {
		os.WriteFile(filepath.Join(dir, m), []byte(""), 0o644) //nolint:errcheck // test helper
	}

	analyzers := buildAnalyzers(dir)

	expected := []string{"go", "rust", "python", "javascript", "java", "csharp", "php", "ruby", "generic"}
	for _, lang := range expected {
		if _, ok := analyzers[lang]; !ok {
			t.Errorf("expected %s analyzer to be registered", lang)
		}
	}
}
