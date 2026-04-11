// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cyclonedx_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravan/cra-toolkit/pkg/formats/cyclonedx"
)

func TestParse_RealCycloneDXSBOM(t *testing.T) {
	f, err := os.Open("../../../testdata/integration/go-reachable/sbom.cdx.json")
	if err != nil {
		t.Fatalf("failed to open test data: %v", err)
	}
	defer f.Close() //nolint:errcheck // test file

	parser := cyclonedx.Parser{}
	components, err := parser.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(components) == 0 {
		t.Fatal("expected at least one component, got 0")
	}

	// Verify we can find the vulnerable component
	found := false
	for _, c := range components {
		if c.Name != "golang.org/x/text" {
			continue
		}
		found = true
		if c.Version == "" {
			t.Error("expected version to be populated for golang.org/x/text")
		}
		if c.PURL == "" {
			t.Error("expected PURL to be populated for golang.org/x/text")
		}
		if c.Type != "golang" {
			t.Errorf("expected Type 'golang', got %q", c.Type)
		}
		break
	}
	if !found {
		t.Error("expected to find component 'golang.org/x/text' in SBOM")
	}
}

func TestParseDirectDeps_WithDependencies(t *testing.T) {
	const sbom = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {"bom-ref": "my-app", "type": "application", "name": "my-app"}
		},
		"components": [
			{"bom-ref": "pkg:npm/body-parser@1.19.0", "name": "body-parser", "version": "1.19.0", "purl": "pkg:npm/body-parser@1.19.0"},
			{"bom-ref": "pkg:npm/qs@6.7.0", "name": "qs", "version": "6.7.0", "purl": "pkg:npm/qs@6.7.0"}
		],
		"dependencies": [
			{"ref": "my-app", "dependsOn": ["pkg:npm/body-parser@1.19.0"]},
			{"ref": "pkg:npm/body-parser@1.19.0", "dependsOn": ["pkg:npm/qs@6.7.0"]}
		]
	}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 1 || got[0] != "body-parser" {
		t.Errorf("ParseDirectDeps: got %v, want [body-parser]", got)
	}
}

func TestParseDirectDeps_PURLWithQualifiers(t *testing.T) {
	// Syft-generated SBOMs use PURLs with package-id qualifiers as dependency refs.
	const sbom = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {"bom-ref": "my-app", "type": "application", "name": "my-app"}
		},
		"components": [
			{"bom-ref": "abc123", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0?package-id=abc123"}
		],
		"dependencies": [
			{"ref": "my-app", "dependsOn": ["pkg:pypi/requests@2.31.0?package-id=abc123"]}
		]
	}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 1 || got[0] != "requests" {
		t.Errorf("ParseDirectDeps: got %v, want [requests]", got)
	}
}

func TestParseDirectDeps_NoMetadataComponent(t *testing.T) {
	const sbom = `{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 0 {
		t.Errorf("ParseDirectDeps: got %v, want []", got)
	}
}

func TestParseDirectDeps_NoDependenciesBlock(t *testing.T) {
	const sbom = `{
		"bomFormat": "CycloneDX",
		"metadata": {"component": {"bom-ref": "my-app"}},
		"components": [{"name": "flask", "purl": "pkg:pypi/flask@2.3.0"}]
	}`
	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(sbom), 0o600); err != nil {
		t.Fatal(err)
	}
	got := cyclonedx.ParseDirectDeps(path)
	if len(got) != 0 {
		t.Errorf("ParseDirectDeps: got %v, want []", got)
	}
}
