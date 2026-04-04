package policykit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// ParsedArtifacts holds all artifacts parsed from CLI inputs.
type ParsedArtifacts struct {
	Components       []formats.Component
	SBOMFormat       string
	SBOMVersion      string
	SBOMName         string
	SBOMVersionField string
	SBOMSupplier     string
	Findings         []formats.Finding
	VEXResults       []formats.VEXResult
	KEV              *KEVCatalog
	Provenance       *Provenance
	Signatures       []SignatureInfo
	Product          *ProductConfig
}

// ProductConfig holds product metadata from a YAML or JSON configuration file.
type ProductConfig struct {
	Exists          bool            `json:"exists"          yaml:"-"`
	Name            string          `json:"name,omitempty"            yaml:"name"`
	Version         string          `json:"version,omitempty"         yaml:"version"`
	ReleaseDate     string          `json:"release_date,omitempty"    yaml:"release_date"`
	SupportEndDate  string          `json:"support_end_date,omitempty" yaml:"support_end_date"`
	SupportYears    int             `json:"support_years,omitempty"   yaml:"-"`
	UpdateMechanism UpdateMechanism `json:"update_mechanism,omitempty" yaml:"update_mechanism"`
}

// UpdateMechanism describes how the product receives security updates.
type UpdateMechanism struct {
	Type                    string `json:"type,omitempty"                     yaml:"type"`
	URL                     string `json:"url,omitempty"                      yaml:"url"`
	AutoUpdateDefault       bool   `json:"auto_update_default,omitempty"      yaml:"auto_update_default"`
	SecurityUpdatesSeparate bool   `json:"security_updates_separate,omitempty" yaml:"security_updates_separate"`
}

// productConfigFile is the top-level structure of a product config file.
type productConfigFile struct {
	Product ProductConfig `json:"product" yaml:"product"`
}

// LoadProductConfig parses a YAML or JSON product configuration file.
// The file must have a top-level "product" key.
func LoadProductConfig(path string) (*ProductConfig, error) {
	cleanPath := filepath.Clean(path)
	data, err := os.ReadFile(cleanPath) //nolint:gosec // path comes from CLI flag
	if err != nil {
		return nil, fmt.Errorf("reading product config %s: %w", cleanPath, err)
	}

	var wrapper productConfigFile

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parsing product config JSON: %w", err)
		}
	default:
		// Treat as YAML (covers .yaml, .yml, and anything else).
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parsing product config YAML: %w", err)
		}
	}

	pc := &wrapper.Product
	pc.Exists = true
	pc.SupportYears = computeSupportYears(pc.ReleaseDate, pc.SupportEndDate)

	return pc, nil
}

// computeSupportYears calculates the number of whole years between two date strings
// in YYYY-MM-DD format. Returns 0 if either date is unparseable.
func computeSupportYears(releaseDate, supportEndDate string) int {
	const layout = "2006-01-02"

	start, err := time.Parse(layout, releaseDate)
	if err != nil {
		return 0
	}
	end, err := time.Parse(layout, supportEndDate)
	if err != nil {
		return 0
	}

	years := end.Year() - start.Year()
	// Subtract a year if the end month/day hasn't been reached yet.
	if end.Month() < start.Month() || (end.Month() == start.Month() && end.Day() < start.Day()) {
		years--
	}
	if years < 0 {
		return 0
	}
	return years
}

// BuildInput assembles the unified OPA input document from parsed artifacts.
func BuildInput(a *ParsedArtifacts) map[string]any {
	input := map[string]any{
		"sbom":       buildSBOM(a),
		"scan":       buildScan(a),
		"vex":        buildVEX(a),
		"kev":        buildKEV(a),
		"provenance": buildProvenance(a),
		"signatures": buildSignatures(a),
		"product":    buildProduct(a),
	}
	return input
}

func buildSBOM(a *ParsedArtifacts) map[string]any {
	components := make([]map[string]any, 0, len(a.Components))
	for i := range a.Components {
		components = append(components, map[string]any{
			"name":    a.Components[i].Name,
			"version": a.Components[i].Version,
			"purl":    a.Components[i].PURL,
			"type":    a.Components[i].Type,
		})
	}
	return map[string]any{
		"format":  a.SBOMFormat,
		"version": a.SBOMVersion,
		"metadata": map[string]any{
			"name":     a.SBOMName,
			"version":  a.SBOMVersionField,
			"supplier": a.SBOMSupplier,
		},
		"components": components,
	}
}

func buildScan(a *ParsedArtifacts) map[string]any {
	findings := make([]map[string]any, 0, len(a.Findings))
	critHighCount := 0
	for i := range a.Findings {
		findings = append(findings, map[string]any{
			"cve":         a.Findings[i].CVE,
			"purl":        a.Findings[i].AffectedPURL,
			"cvss":        a.Findings[i].CVSS,
			"severity":    a.Findings[i].Severity,
			"fix_version": a.Findings[i].FixVersion,
		})
		if a.Findings[i].CVSS >= 7.0 {
			critHighCount++
		}
	}
	return map[string]any{
		"findings":            findings,
		"critical_high_count": critHighCount,
	}
}

func buildVEX(a *ParsedArtifacts) map[string]any {
	statements := make([]map[string]any, 0, len(a.VEXResults))
	for _, v := range a.VEXResults {
		statements = append(statements, map[string]any{
			"cve":           v.CVE,
			"purl":          v.ComponentPURL,
			"status":        string(v.Status),
			"justification": string(v.Justification),
		})
	}
	return map[string]any{
		"statements": statements,
	}
}

func buildKEV(a *ParsedArtifacts) map[string]any {
	if a.KEV == nil {
		return map[string]any{
			"catalog_date": "",
			"cves":         []string{},
		}
	}
	cves := make([]string, 0, len(a.KEV.CVEs))
	for cve := range a.KEV.CVEs {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	return map[string]any{
		"catalog_date": a.KEV.CatalogDate,
		"cves":         cves,
	}
}

func buildProvenance(a *ParsedArtifacts) map[string]any {
	if a.Provenance == nil {
		return map[string]any{"exists": false}
	}
	return map[string]any{
		"exists":      a.Provenance.Exists,
		"builder_id":  a.Provenance.BuilderID,
		"source_repo": a.Provenance.SourceRepo,
		"build_type":  a.Provenance.BuildType,
	}
}

func buildSignatures(a *ParsedArtifacts) map[string]any {
	if len(a.Signatures) == 0 {
		return map[string]any{"exists": false}
	}
	files := make([]map[string]any, 0, len(a.Signatures))
	for _, s := range a.Signatures {
		files = append(files, map[string]any{
			"path":   s.Path,
			"format": s.Format,
		})
	}
	return map[string]any{
		"exists": true,
		"files":  files,
	}
}

func buildProduct(a *ParsedArtifacts) map[string]any {
	if a.Product == nil {
		return map[string]any{"exists": false}
	}
	return map[string]any{
		"exists":           a.Product.Exists,
		"name":             a.Product.Name,
		"version":          a.Product.Version,
		"release_date":     a.Product.ReleaseDate,
		"support_end_date": a.Product.SupportEndDate,
		"support_years":    a.Product.SupportYears,
		"update_mechanism": map[string]any{
			"type":                      a.Product.UpdateMechanism.Type,
			"url":                       a.Product.UpdateMechanism.URL,
			"auto_update_default":       a.Product.UpdateMechanism.AutoUpdateDefault,
			"security_updates_separate": a.Product.UpdateMechanism.SecurityUpdatesSeparate,
		},
	}
}
