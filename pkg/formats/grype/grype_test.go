package grype_test

import (
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats/grype"
)

func TestParser_Parse(t *testing.T) {
	f, err := os.Open("../../../testdata/integration/go-reachable/grype.json")
	if err != nil {
		t.Fatalf("open test data: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	p := grype.Parser{}
	findings, err := p.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	for i, f := range findings {
		if f.CVE == "" {
			t.Errorf("finding[%d]: CVE is empty", i)
		}
		if f.AffectedPURL == "" {
			t.Errorf("finding[%d]: AffectedPURL is empty", i)
		}
		if f.DataSource != "grype" {
			t.Errorf("finding[%d]: DataSource = %q, want %q", i, f.DataSource, "grype")
		}
	}
}
