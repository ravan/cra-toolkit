// Package report generates CRA Article 14 vulnerability notification documents.
// It supports the three-stage pipeline: 24h early warning, 72h notification, 14-day final report.
package report

import "errors"

// ErrNotImplemented is returned by stub functions that are not yet implemented.
var ErrNotImplemented = errors.New("report: not implemented")

// Run executes report generation. This is a stub for the project harness.
func Run() error {
	return ErrNotImplemented
}
