package policykit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func TestBuildInput_FullArtifacts(t *testing.T) { //nolint:gocognit,gocyclo // test validation requires many assertion checks
	arts := &ParsedArtifacts{
		Components: []formats.Component{
			{Name: "golang.org/x/text", Version: "0.3.7", PURL: "pkg:golang/golang.org/x/text@0.3.7", Type: "golang"},
			{Name: "github.com/opencontainers/runc", Version: "1.1.0", PURL: "pkg:golang/github.com/opencontainers/runc@1.1.0", Type: "golang"},
		},
		SBOMFormat:       "cyclonedx",
		SBOMVersion:      "1.5",
		SBOMName:         "myproject",
		SBOMVersionField: "1.0.0",
		SBOMSupplier:     "SUSE",
		Findings: []formats.Finding{
			{
				CVE:          "CVE-2022-32149",
				AffectedPURL: "pkg:golang/golang.org/x/text@0.3.7",
				AffectedName: "golang.org/x/text",
				Severity:     "high",
				CVSS:         7.5,
				FixVersion:   "0.3.8",
			},
			{
				CVE:          "CVE-2024-0001",
				AffectedPURL: "pkg:golang/github.com/opencontainers/runc@1.1.0",
				AffectedName: "runc",
				Severity:     "medium",
				CVSS:         5.3,
				FixVersion:   "1.1.1",
			},
		},
		VEXResults: []formats.VEXResult{
			{
				CVE:           "CVE-2022-32149",
				ComponentPURL: "pkg:golang/golang.org/x/text@0.3.7",
				Status:        formats.StatusNotAffected,
				Justification: formats.JustificationVulnerableCodeNotPresent,
			},
		},
		KEV: &KEVCatalog{
			CatalogDate: "2024-01-15",
			CVEs:        map[string]bool{"CVE-2024-3094": true, "CVE-2024-0001": true},
		},
		Provenance: &Provenance{
			Exists:     true,
			BuilderID:  "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.5.0",
			SourceRepo: "https://github.com/example/myproject",
			BuildType:  "https://slsa.dev/provenance/v1",
		},
		Signatures: []SignatureInfo{
			{Path: "myproject.sig", Format: "cosign"},
		},
		Product: &ProductConfig{
			Exists:         true,
			Name:           "My Product",
			Version:        "1.0.0",
			ReleaseDate:    "2024-01-01",
			SupportEndDate: "2029-01-01",
			SupportYears:   5,
			UpdateMechanism: UpdateMechanism{
				Type:                    "automatic",
				URL:                     "https://update.example.com",
				AutoUpdateDefault:       true,
				SecurityUpdatesSeparate: true,
			},
		},
	}

	input := BuildInput(arts)

	// Verify sbom section.
	sbom, ok := input["sbom"].(map[string]any)
	if !ok {
		t.Fatal("expected sbom key to be map[string]any")
	}
	if sbom["format"] != "cyclonedx" {
		t.Errorf("sbom.format = %v, want cyclonedx", sbom["format"])
	}
	components, ok := sbom["components"].([]map[string]any)
	if !ok {
		t.Fatal("expected sbom.components to be []map[string]any")
	}
	if len(components) != 2 {
		t.Errorf("sbom.components count = %d, want 2", len(components))
	}
	if components[0]["purl"] != "pkg:golang/golang.org/x/text@0.3.7" {
		t.Errorf("sbom.components[0].purl = %v, want pkg:golang/golang.org/x/text@0.3.7", components[0]["purl"])
	}

	// Verify scan section.
	scan, ok := input["scan"].(map[string]any)
	if !ok {
		t.Fatal("expected scan key to be map[string]any")
	}
	if scan["critical_high_count"] != 1 {
		t.Errorf("scan.critical_high_count = %v, want 1", scan["critical_high_count"])
	}

	// Verify kev section.
	kev, ok := input["kev"].(map[string]any)
	if !ok {
		t.Fatal("expected kev key to be map[string]any")
	}
	kevCVEs, ok := kev["cves"].([]string)
	if !ok {
		t.Fatal("expected kev.cves to be []string")
	}
	found := false
	for _, cve := range kevCVEs {
		if cve == "CVE-2024-3094" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("kev.cves does not contain CVE-2024-3094, got %v", kevCVEs)
	}

	// Verify provenance section.
	prov, ok := input["provenance"].(map[string]any)
	if !ok {
		t.Fatal("expected provenance key to be map[string]any")
	}
	if prov["exists"] != true {
		t.Errorf("provenance.exists = %v, want true", prov["exists"])
	}

	// Verify signatures section.
	sigs, ok := input["signatures"].(map[string]any)
	if !ok {
		t.Fatal("expected signatures key to be map[string]any")
	}
	if sigs["exists"] != true {
		t.Errorf("signatures.exists = %v, want true", sigs["exists"])
	}

	// Verify product section.
	prod, ok := input["product"].(map[string]any)
	if !ok {
		t.Fatal("expected product key to be map[string]any")
	}
	if prod["exists"] != true {
		t.Errorf("product.exists = %v, want true", prod["exists"])
	}
}

func TestBuildInput_MissingOptionalArtifacts(t *testing.T) {
	arts := &ParsedArtifacts{
		Components: []formats.Component{
			{Name: "golang.org/x/text", Version: "0.3.7", PURL: "pkg:golang/golang.org/x/text@0.3.7", Type: "golang"},
		},
		SBOMFormat:  "cyclonedx",
		SBOMVersion: "1.5",
		Findings: []formats.Finding{
			{
				CVE:          "CVE-2022-32149",
				AffectedPURL: "pkg:golang/golang.org/x/text@0.3.7",
				Severity:     "medium",
				CVSS:         5.3,
			},
		},
	}

	input := BuildInput(arts)

	// Verify provenance absent.
	prov, ok := input["provenance"].(map[string]any)
	if !ok {
		t.Fatal("expected provenance key to be map[string]any")
	}
	if prov["exists"] != false {
		t.Errorf("provenance.exists = %v, want false", prov["exists"])
	}

	// Verify signatures absent.
	sigs, ok := input["signatures"].(map[string]any)
	if !ok {
		t.Fatal("expected signatures key to be map[string]any")
	}
	if sigs["exists"] != false {
		t.Errorf("signatures.exists = %v, want false", sigs["exists"])
	}

	// Verify product absent.
	prod, ok := input["product"].(map[string]any)
	if !ok {
		t.Fatal("expected product key to be map[string]any")
	}
	if prod["exists"] != false {
		t.Errorf("product.exists = %v, want false", prod["exists"])
	}
}

func TestLoadProductConfig_YAML(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `product:
  name: "Test Product"
  version: "2.0.0"
  release_date: "2024-01-01"
  support_end_date: "2029-01-01"
  update_mechanism:
    type: "automatic"
    url: "https://update.example.com"
    auto_update_default: true
    security_updates_separate: true
`
	path := filepath.Join(dir, "product.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pc, err := LoadProductConfig(path)
	if err != nil {
		t.Fatalf("LoadProductConfig() error: %v", err)
	}

	if !pc.Exists {
		t.Error("expected Exists = true")
	}
	if pc.Name != "Test Product" {
		t.Errorf("Name = %q, want %q", pc.Name, "Test Product")
	}
	if pc.Version != "2.0.0" {
		t.Errorf("Version = %q, want %q", pc.Version, "2.0.0")
	}
	if pc.SupportYears != 5 {
		t.Errorf("SupportYears = %d, want 5", pc.SupportYears)
	}
	if pc.UpdateMechanism.Type != "automatic" {
		t.Errorf("UpdateMechanism.Type = %q, want %q", pc.UpdateMechanism.Type, "automatic")
	}
	if !pc.UpdateMechanism.AutoUpdateDefault {
		t.Error("expected AutoUpdateDefault = true")
	}
}

func TestLoadProductConfig_JSON(t *testing.T) {
	dir := t.TempDir()
	jsonContent := `{
  "product": {
    "name": "JSON Product",
    "version": "3.0.0",
    "release_date": "2023-06-01",
    "support_end_date": "2026-06-01",
    "update_mechanism": {
      "type": "manual",
      "url": "https://downloads.example.com"
    }
  }
}`
	path := filepath.Join(dir, "product.json")
	if err := os.WriteFile(path, []byte(jsonContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pc, err := LoadProductConfig(path)
	if err != nil {
		t.Fatalf("LoadProductConfig() error: %v", err)
	}

	if !pc.Exists {
		t.Error("expected Exists = true")
	}
	if pc.Name != "JSON Product" {
		t.Errorf("Name = %q, want %q", pc.Name, "JSON Product")
	}
	if pc.SupportYears != 3 {
		t.Errorf("SupportYears = %d, want 3", pc.SupportYears)
	}
}

func reachabilityVEXArts() *ParsedArtifacts {
	return &ParsedArtifacts{
		Components: []formats.Component{
			{Name: "PyYAML", Version: "5.3", PURL: "pkg:pypi/pyyaml@5.3", Type: "python"},
		},
		Findings: []formats.Finding{
			{
				CVE:          "CVE-2020-1747",
				AffectedPURL: "pkg:pypi/pyyaml@5.3",
				AffectedName: "PyYAML",
				Severity:     "critical",
				CVSS:         9.8,
			},
		},
		VEXResults: []formats.VEXResult{
			{
				CVE:            "CVE-2020-1747",
				ComponentPURL:  "pkg:pypi/pyyaml@5.3",
				Status:         formats.StatusAffected,
				Confidence:     formats.ConfidenceHigh,
				ResolvedBy:     "reachability_analysis",
				Evidence:       "yaml.load is called",
				AnalysisMethod: "tree_sitter",
				Symbols:        []string{"yaml.load"},
				MaxCallDepth:   3,
				EntryFiles:     []string{"src/app.py"},
				CallPaths: []formats.CallPath{
					{
						Nodes: []formats.CallNode{
							{Symbol: "app.main", File: "src/app.py", Line: 10},
							{Symbol: "app.process", File: "src/app.py", Line: 25},
							{Symbol: "yaml.load", File: "yaml/__init__.py", Line: 100},
						},
					},
				},
			},
		},
	}
}

func getVEXStatement(t *testing.T, arts *ParsedArtifacts) map[string]any {
	t.Helper()
	input := BuildInput(arts)
	vexSection, ok := input["vex"].(map[string]any)
	if !ok {
		t.Fatal("expected vex key to be map[string]any")
	}
	stmts, ok := vexSection["statements"].([]map[string]any)
	if !ok {
		t.Fatal("expected vex.statements to be []map[string]any")
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	return stmts[0]
}

func TestBuildInput_VEXReachabilityFields_ScalarFields(t *testing.T) {
	s := getVEXStatement(t, reachabilityVEXArts())

	if s["confidence"] != "high" {
		t.Errorf("confidence = %v, want high", s["confidence"])
	}
	if s["resolved_by"] != "reachability_analysis" {
		t.Errorf("resolved_by = %v, want reachability_analysis", s["resolved_by"])
	}
	if s["analysis_method"] != "tree_sitter" {
		t.Errorf("analysis_method = %v, want tree_sitter", s["analysis_method"])
	}
	if s["max_call_depth"] != 3 {
		t.Errorf("max_call_depth = %v, want 3", s["max_call_depth"])
	}
}

func TestBuildInput_VEXReachabilityFields_SliceFields(t *testing.T) {
	s := getVEXStatement(t, reachabilityVEXArts())

	symbols, ok := s["symbols"].([]string)
	if !ok {
		t.Fatal("expected symbols to be []string")
	}
	if len(symbols) != 1 || symbols[0] != "yaml.load" {
		t.Errorf("symbols = %v, want [yaml.load]", symbols)
	}

	entryFiles, ok := s["entry_files"].([]string)
	if !ok {
		t.Fatal("expected entry_files to be []string")
	}
	if len(entryFiles) != 1 || entryFiles[0] != "src/app.py" {
		t.Errorf("entry_files = %v, want [src/app.py]", entryFiles)
	}
}

func TestBuildInput_VEXReachabilityFields_CallPaths(t *testing.T) {
	s := getVEXStatement(t, reachabilityVEXArts())

	callPaths, ok := s["call_paths"].([][]map[string]any)
	if !ok {
		t.Fatal("expected call_paths to be [][]map[string]any")
	}
	if len(callPaths) != 1 {
		t.Fatalf("call_paths count = %d, want 1", len(callPaths))
	}
	if len(callPaths[0]) != 3 {
		t.Fatalf("call_paths[0] node count = %d, want 3", len(callPaths[0]))
	}
	node := callPaths[0][0]
	if node["symbol"] != "app.main" {
		t.Errorf("call_paths[0][0].symbol = %v, want app.main", node["symbol"])
	}
	if node["file"] != "src/app.py" {
		t.Errorf("call_paths[0][0].file = %v, want src/app.py", node["file"])
	}
	if node["line"] != 10 {
		t.Errorf("call_paths[0][0].line = %v, want 10", node["line"])
	}
}
