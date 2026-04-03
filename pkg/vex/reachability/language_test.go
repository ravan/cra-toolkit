package reachability_test

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
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

func createFile(t *testing.T, dir, name string) (*os.File, error) {
	t.Helper()
	return os.Create(filepath.Join(dir, name)) //nolint:gosec // test helper with controlled paths
}
