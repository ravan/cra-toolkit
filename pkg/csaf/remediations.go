package csaf

import (
	"fmt"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func addRemediations(vulns []vulnerability, findings []formats.Finding) []vulnerability {
	findingLookup := make(map[string]*formats.Finding, len(findings))
	for i := range findings {
		f := &findings[i]
		findingLookup[f.CVE+"|"+f.AffectedPURL] = f
	}
	for i := range vulns {
		v := &vulns[i]
		allProducts := collectAllProducts(&v.ProductStatus)
		for _, pid := range allProducts {
			f, ok := findingLookup[v.CVE+"|"+pid]
			if !ok {
				continue
			}
			if f.FixVersion != "" {
				v.Remediations = append(v.Remediations, remediation{
					Category:   "vendor_fix",
					Details:    fmt.Sprintf("Upgrade %s to version %s or later.", f.AffectedName, f.FixVersion),
					ProductIDs: []string{pid},
				})
			} else {
				v.Remediations = append(v.Remediations, remediation{
					Category:   "none_available",
					Details:    fmt.Sprintf("No fix is currently available for %s.", f.AffectedName),
					ProductIDs: []string{pid},
				})
			}
		}
	}
	return vulns
}
