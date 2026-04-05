// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import "github.com/ravan/suse-cra-toolkit/pkg/formats"

// Filter is a single step in the VEX determination pipeline.
type Filter interface {
	Name() string
	Evaluate(finding *formats.Finding, components []formats.Component) (result Result, resolved bool)
}

// RunChain runs a list of filters in order and returns the first resolved result.
// If no filter resolves the finding, it returns a default under_investigation result.
func RunChain(filters []Filter, finding *formats.Finding, components []formats.Component) Result {
	for _, f := range filters {
		result, resolved := f.Evaluate(finding, components)
		if resolved {
			return result
		}
	}
	return Result{
		CVE:           finding.CVE,
		ComponentPURL: finding.AffectedPURL,
		Status:        formats.StatusUnderInvestigation,
		Confidence:    formats.ConfidenceLow,
		ResolvedBy:    "default",
		Evidence:      "No filter could determine VEX status. Queued for manual review.",
	}
}
