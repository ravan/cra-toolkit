// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package reachability_test

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/vex/reachability"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "testdata", "integration")
}

func TestDetectLanguages_Go(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "go-reachable", "source")
	langs := reachability.DetectLanguages(dir)
	if len(langs) != 1 || langs[0] != "go" {
		t.Fatalf("expected [go], got %v", langs)
	}
}

func TestDetectLanguages_Python(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "python-reachable", "source")
	langs := reachability.DetectLanguages(dir)
	if len(langs) != 1 || langs[0] != "python" {
		t.Fatalf("expected [python], got %v", langs)
	}
}

func TestDetectLanguages_Rust(t *testing.T) {
	dir := filepath.Join(testdataDir(t), "rust-reachable", "source")
	langs := reachability.DetectLanguages(dir)
	if len(langs) != 1 || langs[0] != "rust" {
		t.Fatalf("expected [rust], got %v", langs)
	}
}

func TestDetectLanguages_Empty(t *testing.T) {
	dir := t.TempDir()
	langs := reachability.DetectLanguages(dir)
	if len(langs) != 0 {
		t.Fatalf("expected no languages, got %v", langs)
	}
}

func TestDetectLanguages_Multiple(t *testing.T) {
	dir := t.TempDir()
	// Create markers for go and python.
	for _, name := range []string{"go.mod", "requirements.txt"} {
		f, err := createFile(t, dir, name)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}

	langs := reachability.DetectLanguages(dir)
	sort.Strings(langs)
	if len(langs) != 2 || langs[0] != "go" || langs[1] != "python" {
		t.Fatalf("expected [go python], got %v", langs)
	}
}

func TestDetectLanguages_AllSupported(t *testing.T) {
	dir := t.TempDir()

	// Create markers for all supported languages
	markers := map[string]string{
		"go.mod":           "go",
		"Cargo.toml":       "rust",
		"package.json":     "javascript",
		"requirements.txt": "python",
		"pom.xml":          "java",
		"composer.json":    "php",
		"Gemfile":          "ruby",
	}
	for file := range markers {
		os.WriteFile(filepath.Join(dir, file), []byte(""), 0o644) //nolint:errcheck,gosec // test helper
	}

	langs := reachability.DetectLanguages(dir)
	if len(langs) < 7 {
		t.Errorf("expected at least 7 languages, got %d: %v", len(langs), langs)
	}
}

func TestDetectLanguages_CSharp(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "TestApp.csproj"), []byte(""), 0o644) //nolint:errcheck,gosec // test helper

	langs := reachability.DetectLanguages(dir)
	found := false
	for _, l := range langs {
		if l == "csharp" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected csharp to be detected, got %v", langs)
	}
}

func TestNormalizeLanguage(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"dotnet", "csharp"},
		{"csharp", "csharp"},
		{"go", "go"},
		{"python", "python"},
		{"javascript", "javascript"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := reachability.NormalizeLanguage(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeLanguage(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func createFile(t *testing.T, dir, name string) (*os.File, error) {
	t.Helper()
	return os.Create(filepath.Join(dir, name)) //nolint:gosec // test helper with controlled paths
}
