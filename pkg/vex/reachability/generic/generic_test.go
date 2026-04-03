package generic_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/generic"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")
}

func skipIfNoRipgrep(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("rg (ripgrep) not installed, skipping")
	}
}

func TestAnalyzer_Language(t *testing.T) {
	a := generic.New("python")
	if lang := a.Language(); lang != "python" {
		t.Fatalf("expected 'python', got %q", lang)
	}

	a2 := generic.New("")
	if lang := a2.Language(); lang != "generic" {
		t.Fatalf("expected 'generic', got %q", lang)
	}
}

func TestAnalyze_PythonReachable(t *testing.T) {
	skipIfNoRipgrep(t)

	sourceDir := filepath.Join(testdataDir(t), "python-reachable", "source")
	analyzer := generic.New("python")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Reachable {
		t.Error("expected Reachable=true, got false")
	}
	if result.Confidence != formats.ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium, got %v", result.Confidence)
	}
	if len(result.Symbols) == 0 {
		t.Error("expected at least one symbol in result")
	}
}

func TestAnalyze_PythonNotReachable(t *testing.T) {
	skipIfNoRipgrep(t)

	sourceDir := filepath.Join(testdataDir(t), "python-not-reachable", "source")
	analyzer := generic.New("python")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false, got true")
	}
	if result.Confidence != formats.ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium, got %v", result.Confidence)
	}
}

func TestAnalyze_NoSymbols_ImportFound(t *testing.T) {
	skipIfNoRipgrep(t)

	sourceDir := filepath.Join(testdataDir(t), "python-reachable", "source")
	analyzer := generic.New("python")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2020-1747",
		AffectedPURL: "pkg:pypi/PyYAML@5.3",
		AffectedName: "PyYAML",
		Language:     "python",
		// No symbols specified.
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With no symbol info but import found, should be reachable (medium confidence).
	if !result.Reachable {
		t.Error("expected Reachable=true when import found with no symbols")
	}
}

func TestNormalizeModuleName_PyPI(t *testing.T) {
	tests := []struct {
		name     string
		language string
		want     string
	}{
		{"PyYAML", "python", "yaml"},
		{"Pillow", "python", "PIL"},
		{"scikit-learn", "python", "sklearn"},
		{"beautifulsoup4", "python", "bs4"},
		{"requests", "python", "requests"},
		{"PyYAML", "javascript", "PyYAML"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.language, func(t *testing.T) {
			got := generic.NormalizeModuleName(tt.name, tt.language)
			if got != tt.want {
				t.Errorf("NormalizeModuleName(%q, %q) = %q, want %q", tt.name, tt.language, got, tt.want)
			}
		})
	}
}
