package formats

import "io"

// Finding represents a vulnerability finding from a scanner.
type Finding struct {
	CVE              string   // CVE identifier (e.g. "CVE-2022-32149")
	AffectedPURL     string   // PURL of the affected component
	AffectedName     string   // package name
	AffectedVersions string   // affected version range expression (e.g. "< 0.3.8")
	FixVersion       string   // version that fixes the vulnerability (empty if no fix)
	Severity         string   // "critical", "high", "medium", "low", "unknown"
	CVSS             float64  // CVSS score (0-10)
	CVSSVector       string   // CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...")
	Description      string   // vulnerability description
	DataSource       string   // where this finding came from (e.g. "grype", "trivy", "sarif")
	Symbols          []string // vulnerable function/symbol names (if known)
	Platforms        []string // affected platforms (e.g. ["linux", "windows"])
	Language         string   // programming language of affected component (e.g. "go", "rust", "python")
}

// ScanParser parses vulnerability scan results and returns findings.
type ScanParser interface {
	Parse(r io.Reader) ([]Finding, error)
}
