// Package formats provides shared types for SBOM, VEX, CSAF, and SARIF documents.
package formats

import "io"

// Component represents a software component extracted from an SBOM.
type Component struct {
	Name      string            // human-readable name
	Version   string            // installed version
	PURL      string            // Package URL (canonical identifier)
	Type      string            // PURL type: "golang", "npm", "pypi", "cargo", etc.
	Namespace string            // PURL namespace: e.g. "github.com/foo" for Go
	Platform  string            // target platform qualifier from PURL (e.g. "linux", "windows")
	Arch      string            // architecture qualifier from PURL (e.g. "amd64", "arm64")
	Hashes    map[string]string // algorithm -> hash value
	Supplier  string            // component supplier/vendor
}

// SBOMParser parses an SBOM document and returns its components.
type SBOMParser interface {
	Parse(r io.Reader) ([]Component, error)
}
