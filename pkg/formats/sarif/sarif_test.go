package sarif_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats/sarif"
)

const testDataPath = "../../../testdata/integration/go-reachable/results.sarif"

func TestParser_Parse_WithFile(t *testing.T) {
	f, err := os.Open(testDataPath)
	if err != nil {
		t.Skipf("no SARIF test data at %s: %v", testDataPath, err)
	}
	defer f.Close() //nolint:errcheck // test file

	p := sarif.Parser{}
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
		if f.DataSource != "sarif" {
			t.Errorf("finding[%d]: DataSource = %q, want %q", i, f.DataSource, "sarif")
		}
	}
}

func TestParser_Parse_Inline(t *testing.T) {
	// Synthetic SARIF document with a CVE in the ruleId.
	doc := `{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"results": [
				{
					"ruleId": "CVE-2022-32149",
					"level": "error",
					"message": {"text": "Denial of service via Accept-Language header"}
				},
				{
					"ruleId": "SOME-RULE",
					"level": "warning",
					"message": {"text": "See CVE-2021-44228 for details"}
				}
			]
		}]
	}`

	p := sarif.Parser{}
	findings, err := p.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].CVE != "CVE-2022-32149" {
		t.Errorf("finding[0].CVE = %q, want CVE-2022-32149", findings[0].CVE)
	}
	if findings[0].Severity != "high" {
		t.Errorf("finding[0].Severity = %q, want high", findings[0].Severity)
	}
	if findings[1].CVE != "CVE-2021-44228" {
		t.Errorf("finding[1].CVE = %q, want CVE-2021-44228", findings[1].CVE)
	}
	if findings[1].Severity != "medium" {
		t.Errorf("finding[1].Severity = %q, want medium", findings[1].Severity)
	}
	for i, f := range findings {
		if f.DataSource != "sarif" {
			t.Errorf("finding[%d]: DataSource = %q, want sarif", i, f.DataSource)
		}
	}
}
