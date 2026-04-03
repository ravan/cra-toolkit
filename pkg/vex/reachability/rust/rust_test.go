package rust_test

import (
	"os/exec"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/rust"
)

func skipIfNoCargoScan(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("cargo-scan"); err != nil {
		t.Skip("cargo-scan not installed, skipping")
	}
}

func TestAnalyzer_Language(t *testing.T) {
	a := rust.New()
	if lang := a.Language(); lang != "rust" {
		t.Fatalf("expected language 'rust', got %q", lang)
	}
}

func TestAnalyze_ReachableVulnerability(t *testing.T) {
	skipIfNoCargoScan(t)
	// TODO: implement when cargo-scan is available.
}

func TestAnalyze_NotReachableVulnerability(t *testing.T) {
	skipIfNoCargoScan(t)
	// TODO: implement when cargo-scan is available.
}
