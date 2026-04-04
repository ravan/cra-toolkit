package csaf

import "github.com/ravan/suse-cra-toolkit/pkg/formats"

func enrichScores(vulns []vulnerability, findings []formats.Finding) []vulnerability {
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
			if !ok || f.CVSS == 0 {
				continue
			}
			v.Scores = append(v.Scores, score{
				Products: []string{pid},
				CVSS3: &cvssV3{
					Version:      "3.1",
					VectorString: f.CVSSVector,
					BaseScore:    f.CVSS,
					BaseSeverity: cvssToSeverity(f.CVSS),
				},
			})
		}
	}
	return vulns
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func collectAllProducts(ps *productStatus) []string {
	var all []string
	all = append(all, ps.KnownAffected...)
	all = append(all, ps.KnownNotAffected...)
	all = append(all, ps.Fixed...)
	all = append(all, ps.UnderInvestigation...)
	return all
}
