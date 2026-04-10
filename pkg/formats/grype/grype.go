// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package grype

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

// Parser parses Grype JSON scan output.
type Parser struct{}

type grypeReport struct {
	Matches []match `json:"matches"`
}

type match struct {
	Vulnerability          vulnerability   `json:"vulnerability"`
	RelatedVulnerabilities []vulnerability `json:"relatedVulnerabilities"`
	Artifact               artifact        `json:"artifact"`
}

type vulnerability struct {
	ID                  string   `json:"id"`
	Severity            string   `json:"severity"`
	Description         string   `json:"description"`
	Fix                 fix      `json:"fix"`
	CVSS                []cvss   `json:"cvss"`
	VulnerableFunctions []string `json:"vulnerableFunctions,omitempty"` // optional: known vulnerable function names
}

type fix struct {
	Versions []string `json:"versions"`
}

type cvss struct {
	Vector  string      `json:"vector"`
	Metrics cvssMetrics `json:"metrics"`
}

type cvssMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type artifact struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	PURL     string `json:"purl"`
	Language string `json:"language"`
}

// Parse reads Grype JSON output and returns a slice of findings.
func (p Parser) Parse(r io.Reader) ([]formats.Finding, error) {
	var report grypeReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, err
	}

	findings := make([]formats.Finding, 0, len(report.Matches))
	for i := range report.Matches {
		cve := cveID(&report.Matches[i])

		m := &report.Matches[i]

		var fixVersion string
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixVersion = m.Vulnerability.Fix.Versions[0]
		}

		var cvssScore float64
		var cvssVector string
		if len(m.Vulnerability.CVSS) > 0 {
			cvssScore = m.Vulnerability.CVSS[0].Metrics.BaseScore
			cvssVector = m.Vulnerability.CVSS[0].Vector
		}

		findings = append(findings, formats.Finding{
			CVE:             cve,
			AffectedPURL:    m.Artifact.PURL,
			AffectedName:    m.Artifact.Name,
			AffectedVersion: m.Artifact.Version,
			FixVersion:      fixVersion,
			Severity:        strings.ToLower(m.Vulnerability.Severity),
			CVSS:            cvssScore,
			CVSSVector:      cvssVector,
			Description:     m.Vulnerability.Description,
			DataSource:      "grype",
			Language:        m.Artifact.Language,
			Symbols:         m.Vulnerability.VulnerableFunctions,
		})
	}
	return findings, nil
}

// cveID returns the CVE identifier for a match, preferring a CVE-prefixed ID
// from relatedVulnerabilities over the primary vulnerability ID.
func cveID(m *match) string {
	for _, rv := range m.RelatedVulnerabilities {
		if strings.HasPrefix(rv.ID, "CVE-") {
			return rv.ID
		}
	}
	return m.Vulnerability.ID
}
