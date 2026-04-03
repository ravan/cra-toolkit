// Package vex implements VEX status determination using deterministic filters.
// It takes an SBOM and vulnerability scan results and auto-determines VEX status
// for each CVE using component presence, version range, platform, and patch checks.
package vex

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("vex: not implemented")

// Run executes VEX status determination. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
