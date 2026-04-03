// Package evidence bundles compliance outputs (SBOM, VEX, provenance, scans, policy reports)
// into a signed, versioned CRA evidence package for Annex VII technical documentation.
package evidence

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("evidence: not implemented")

// Run executes evidence bundling. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
