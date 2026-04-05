// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package sarif

import (
	"encoding/json"
	"io"
	"regexp"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// Parser parses SARIF (Static Analysis Results Interchange Format) scan output.
type Parser struct{}

type sarifDocument struct {
	Runs []run `json:"runs"`
}

type run struct {
	Results []sarifResult `json:"results"`
}

type sarifResult struct {
	RuleID  string       `json:"ruleId"`
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// Parse reads SARIF JSON output and returns a slice of findings.
// CVE identifiers are extracted from ruleId and message.text using a regex.
// Each unique CVE found per result produces one Finding.
func (p Parser) Parse(r io.Reader) ([]formats.Finding, error) {
	var doc sarifDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}

	var findings []formats.Finding
	for _, run := range doc.Runs {
		for _, res := range run.Results {
			cve := extractCVE(res)
			if cve == "" {
				continue
			}
			findings = append(findings, formats.Finding{
				CVE:         cve,
				Severity:    mapLevel(res.Level),
				Description: res.Message.Text,
				DataSource:  "sarif",
			})
		}
	}
	return findings, nil
}

// extractCVE returns the first CVE identifier found in ruleId or message text.
func extractCVE(res sarifResult) string {
	if m := cvePattern.FindString(res.RuleID); m != "" {
		return m
	}
	return cvePattern.FindString(res.Message.Text)
}

// mapLevel maps SARIF levels to normalised severity strings.
func mapLevel(level string) string {
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "unknown"
	}
}
