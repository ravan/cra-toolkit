// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package python_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/vex/reachability/python"
)

func TestAnalyzer_Language(t *testing.T) {
	a := python.New()
	if lang := a.Language(); lang != "python" {
		t.Fatalf("expected 'python', got %q", lang)
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestAnalyze_PythonReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "requirements.txt"), []byte("PyYAML==5.3\n"))
	writeFile(t, filepath.Join(dir, "main.py"), []byte(`from handler import process_config

if __name__ == "__main__":
    process_config("config.yml")
`))
	writeFile(t, filepath.Join(dir, "handler.py"), []byte(`import yaml

def process_config(path):
    with open(path) as f:
        return yaml.load(f)
`))

	analyzer := python.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Reachable {
		t.Error("expected Reachable=true, got false")
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

func TestAnalyze_PythonNotReachable(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "requirements.txt"), []byte("PyYAML==5.3\n"))
	writeFile(t, filepath.Join(dir, "app.py"), []byte(`import yaml

def process():
    # Uses safe_load only, not the vulnerable load()
    data = yaml.safe_load("key: value")
    return data
`))

	analyzer := python.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, dir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false, got true")
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}

func TestIntegration_PythonTreesitterReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "python-treesitter-reachable", "source")
	analyzer := python.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if !result.Reachable {
		t.Error("expected Reachable=true")
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

func TestIntegration_PythonTreesitterNotReachable(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	fixtureBase := filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")

	sourceDir := filepath.Join(fixtureBase, "python-treesitter-not-reachable", "source")
	analyzer := python.New()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Symbols:      []string{"load"},
		Language:     "python",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false")
	}
	if len(result.Paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(result.Paths))
	}
}

func TestPython_Analyzer_TransitiveShortCircuit(t *testing.T) {
	a := &python.Analyzer{} // Transitive is nil → must fall back
	_, err := a.Analyze(context.Background(), t.TempDir(), &formats.Finding{
		AffectedName: "urllib3",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
}

func TestPython_Analyzer_AcceptsTransitiveField(t *testing.T) {
	a := &python.Analyzer{Transitive: nil}
	_ = a // compile-time check only: struct must accept Transitive field
}
