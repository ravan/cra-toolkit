// Package policykit implements CRA Annex I policy evaluation using embedded OPA/Rego policies.
// It evaluates SBOM, VEX, and provenance artifacts against machine-checkable CRA rules.
package policykit

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("policykit: not implemented")

// Run executes CRA policy evaluation. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
