package golang_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/golang"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "..", "testdata", "integration")
}

func skipIfNoGovulncheck(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("govulncheck"); err != nil {
		t.Skip("govulncheck not installed, skipping")
	}
}

func TestAnalyze_ReachableVulnerability(t *testing.T) {
	skipIfNoGovulncheck(t)

	sourceDir := filepath.Join(testdataDir(t), "go-reachable", "source")
	analyzer := golang.New()

	if lang := analyzer.Language(); lang != "go" {
		t.Fatalf("expected language 'go', got %q", lang)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-32149",
		AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7",
		AffectedName: "golang.org/x/text",
		Symbols:      []string{"ParseAcceptLanguage"},
		Language:     "go",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
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
}

func TestAnalyze_NotReachableVulnerability(t *testing.T) {
	skipIfNoGovulncheck(t)

	sourceDir := filepath.Join(testdataDir(t), "go-not-reachable", "source")
	analyzer := golang.New()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	finding := formats.Finding{
		CVE:          "CVE-2022-32149",
		AffectedPURL: "pkg:golang/golang.org/x/text@v0.3.7",
		AffectedName: "golang.org/x/text",
		Symbols:      []string{"ParseAcceptLanguage"},
		Language:     "go",
	}

	result, err := analyzer.Analyze(ctx, sourceDir, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Reachable {
		t.Error("expected Reachable=false, got true")
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
}

func TestParseGovulncheckOutput_Reachable(t *testing.T) {
	// Test parsing with embedded JSON to avoid needing govulncheck installed.
	data := []byte(`{"config":{"protocol_version":"v1.0.0"}}
{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8","trace":[{"module":"golang.org/x/text","version":"v0.3.7"}]}}
{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8","trace":[{"module":"golang.org/x/text","version":"v0.3.7","package":"golang.org/x/text/language"}]}}
{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8","trace":[{"module":"golang.org/x/text","version":"v0.3.7","package":"golang.org/x/text/language","function":"ParseAcceptLanguage"},{"module":"example.com/test","package":"example.com/test","function":"main"}]}}
`)

	finding := formats.Finding{
		CVE:          "CVE-2022-32149",
		AffectedName: "golang.org/x/text",
	}

	result, err := golang.ParseGovulncheckOutput(data, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Reachable {
		t.Error("expected Reachable=true")
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
	if len(result.Symbols) == 0 || result.Symbols[0] != "ParseAcceptLanguage" {
		t.Errorf("expected symbols=[ParseAcceptLanguage], got %v", result.Symbols)
	}
}

func TestParseGovulncheckOutput_NotReachable(t *testing.T) {
	data := []byte(`{"config":{"protocol_version":"v1.0.0"}}
{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8","trace":[{"module":"golang.org/x/text","version":"v0.3.7"}]}}
{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8","trace":[{"module":"golang.org/x/text","version":"v0.3.7","package":"golang.org/x/text/language"}]}}
`)

	finding := formats.Finding{
		CVE:          "CVE-2022-32149",
		AffectedName: "golang.org/x/text",
	}

	result, err := golang.ParseGovulncheckOutput(data, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reachable {
		t.Error("expected Reachable=false")
	}
	if result.Confidence != formats.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got %v", result.Confidence)
	}
}

func TestParseGovulncheckOutput_NoMatch(t *testing.T) {
	data := []byte(`{"config":{"protocol_version":"v1.0.0"}}
{"finding":{"osv":"GO-2022-9999","fixed_version":"v1.0.0","trace":[{"module":"github.com/other/module","version":"v0.1.0"}]}}
`)

	finding := formats.Finding{
		CVE:          "CVE-2022-32149",
		AffectedName: "golang.org/x/text",
	}

	result, err := golang.ParseGovulncheckOutput(data, &finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reachable {
		t.Error("expected Reachable=false")
	}
}
