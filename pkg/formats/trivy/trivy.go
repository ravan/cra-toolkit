// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// Parser parses Trivy JSON scan output.
type Parser struct{}

type trivyReport struct {
	Results []result `json:"Results"`
}

type result struct {
	Type            string          `json:"Type"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
}

type vulnerability struct {
	VulnerabilityID     string               `json:"VulnerabilityID"`
	PkgName             string               `json:"PkgName"`
	PkgIdentifier       pkgIdentifier        `json:"PkgIdentifier"`
	InstalledVersion    string               `json:"InstalledVersion"`
	FixedVersion        string               `json:"FixedVersion"`
	Severity            string               `json:"Severity"`
	Description         string               `json:"Description"`
	CVSS                map[string]cvssEntry `json:"CVSS"`
	VulnerableFunctions []string             `json:"VulnerableFunctions,omitempty"`
}

type pkgIdentifier struct {
	PURL string `json:"PURL"`
}

type cvssEntry struct {
	V3Score float64 `json:"V3Score"`
}

// Parse reads Trivy JSON output and returns a slice of findings.
func (p Parser) Parse(r io.Reader) ([]formats.Finding, error) {
	var report trivyReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, err
	}

	var findings []formats.Finding
	for _, res := range report.Results {
		purlType := mapType(res.Type)
		for i := range res.Vulnerabilities {
			v := &res.Vulnerabilities[i]
			purl := v.PkgIdentifier.PURL
			if purl == "" {
				purl = buildPURL(purlType, v.PkgName, v.InstalledVersion)
			}

			findings = append(findings, formats.Finding{
				CVE:          v.VulnerabilityID,
				AffectedPURL: purl,
				AffectedName: v.PkgName,
				FixVersion:   v.FixedVersion,
				Severity:     strings.ToLower(v.Severity),
				CVSS:         bestCVSS(v.CVSS),
				Description:  v.Description,
				DataSource:   "trivy",
				Language:     languageForType(res.Type),
				Symbols:      v.VulnerableFunctions,
			})
		}
	}
	return findings, nil
}

// mapType maps Trivy's Result.Type to a PURL package type.
func mapType(t string) string {
	switch strings.ToLower(t) {
	case "gomod", "gobinary":
		return "golang"
	case "npm", "yarn", "pnpm":
		return "npm"
	case "pip", "pipenv", "poetry":
		return "pypi"
	case "cargo":
		return "cargo"
	case "gem":
		return "gem"
	case "maven", "gradle":
		return "maven"
	case "nuget":
		return "nuget"
	default:
		return "generic"
	}
}

// languageForType maps Trivy's Result.Type to a language name.
func languageForType(t string) string {
	switch strings.ToLower(t) {
	case "gomod", "gobinary":
		return "go"
	case "npm", "yarn", "pnpm":
		return "javascript"
	case "pip", "pipenv", "poetry":
		return "python"
	case "cargo":
		return "rust"
	case "gem":
		return "ruby"
	case "maven", "gradle":
		return "java"
	default:
		return ""
	}
}

func buildPURL(purlType, name, version string) string {
	if version == "" {
		return fmt.Sprintf("pkg:%s/%s", purlType, name)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
}

// bestCVSS returns the highest CVSS v3 score from the map.
func bestCVSS(scores map[string]cvssEntry) float64 {
	var best float64
	for _, entry := range scores {
		if entry.V3Score > best {
			best = entry.V3Score
		}
	}
	return best
}
