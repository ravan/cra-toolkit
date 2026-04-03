// Package csaf converts vulnerability scanner output and VEX assessments
// into CSAF 2.0 advisories for downstream user notification per CRA Art. 14(8).
package csaf

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("csaf: not implemented")

// Run executes CSAF advisory generation. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
