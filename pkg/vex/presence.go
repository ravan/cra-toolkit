// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package vex

import (
	"fmt"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

// presenceFilter resolves findings when the affected component is not present in the SBOM.
type presenceFilter struct{}

// NewPresenceFilter returns a Filter that marks a finding not_affected when the
// affected component (matched by type+namespace+name, ignoring version) is absent
// from the SBOM component list.
func NewPresenceFilter() Filter {
	return &presenceFilter{}
}

func (f *presenceFilter) Name() string { return "presence" }

func (f *presenceFilter) Evaluate(finding *formats.Finding, components []formats.Component) (Result, bool) {
	affectedPURL, err := packageurl.FromString(finding.AffectedPURL)
	if err != nil {
		// Can't parse the PURL — skip this filter.
		return Result{}, false
	}

	for i := range components {
		compPURL, err := packageurl.FromString(components[i].PURL)
		if err != nil {
			continue
		}
		if compPURL.Type == affectedPURL.Type &&
			compPURL.Namespace == affectedPURL.Namespace &&
			compPURL.Name == affectedPURL.Name {
			// Component IS present — cannot mark as not_affected.
			return Result{}, false
		}
	}

	// Component is absent from the SBOM.
	return Result{
		CVE:           finding.CVE,
		ComponentPURL: finding.AffectedPURL,
		Status:        formats.StatusNotAffected,
		Justification: formats.JustificationComponentNotPresent,
		Confidence:    formats.ConfidenceHigh,
		ResolvedBy:    "presence",
		Evidence:      fmt.Sprintf("Component %s/%s/%s not found in SBOM.", affectedPURL.Type, affectedPURL.Namespace, affectedPURL.Name),
	}, true
}
