package csaf

import (
	"fmt"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

func buildDocumentReferences(findings []formats.Finding) []reference {
	seen := make(map[string]bool)
	refs := make([]reference, 0, len(findings))
	for i := range findings {
		cve := findings[i].CVE
		if seen[cve] {
			continue
		}
		seen[cve] = true
		refs = append(refs, reference{
			Category: "external",
			Summary:  fmt.Sprintf("NVD entry for %s", cve),
			URL:      fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
		})
	}
	return refs
}

func buildVulnReferences(cve string) []reference {
	return []reference{
		{
			Category: "external",
			Summary:  fmt.Sprintf("NVD entry for %s", cve),
			URL:      fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve),
		},
		{
			Category: "external",
			Summary:  fmt.Sprintf("MITRE entry for %s", cve),
			URL:      fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cve),
		},
	}
}
