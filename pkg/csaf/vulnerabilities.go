// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package csaf

import "github.com/ravan/suse-cra-toolkit/pkg/formats"

// mapVulnerabilities correlates scanner findings with VEX results and returns
// CSAF vulnerability entries grouped by CVE in finding order.
func mapVulnerabilities(findings []formats.Finding, vexResults []formats.VEXResult) []vulnerability { //nolint:gocyclo // VEX status mapping requires branching
	// Build lookup: "CVE|PURL" -> VEXResult
	vexLookup := make(map[string]formats.VEXResult, len(vexResults))
	for i := range vexResults {
		vr := &vexResults[i]
		vexLookup[vr.CVE+"|"+vr.ComponentPURL] = *vr
	}

	// Group findings by CVE, preserving order
	vulnMap := make(map[string]*vulnerability)
	var vulnOrder []string

	for i := range findings {
		f := &findings[i]
		productID := f.AffectedPURL

		if _, exists := vulnMap[f.CVE]; !exists {
			vulnMap[f.CVE] = &vulnerability{CVE: f.CVE}
			vulnOrder = append(vulnOrder, f.CVE)
		}
		v := vulnMap[f.CVE]

		vr, hasVEX := vexLookup[f.CVE+"|"+productID]
		if !hasVEX {
			v.ProductStatus.UnderInvestigation = append(v.ProductStatus.UnderInvestigation, productID)
			continue
		}

		switch vr.Status {
		case formats.StatusNotAffected:
			v.ProductStatus.KnownNotAffected = append(v.ProductStatus.KnownNotAffected, productID)
			if vr.Justification != "" {
				v.Flags = append(v.Flags, flag{Label: string(vr.Justification), ProductIDs: []string{productID}})
			}
		case formats.StatusAffected:
			v.ProductStatus.KnownAffected = append(v.ProductStatus.KnownAffected, productID)
		case formats.StatusFixed:
			v.ProductStatus.Fixed = append(v.ProductStatus.Fixed, productID)
		case formats.StatusUnderInvestigation:
			v.ProductStatus.UnderInvestigation = append(v.ProductStatus.UnderInvestigation, productID)
		}
	}

	vulns := make([]vulnerability, 0, len(vulnOrder))
	for _, cve := range vulnOrder {
		vulns = append(vulns, *vulnMap[cve])
	}
	return vulns
}
