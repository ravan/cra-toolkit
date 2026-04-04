package csaf

import "github.com/ravan/suse-cra-toolkit/pkg/formats"

func buildProductTree(components []formats.Component, publisherName string) productTree {
	productBranches := make([]branch, 0, len(components))
	for i := range components {
		c := &components[i]
		// Skip components without PURLs (e.g. file-type entries from SBOM tools).
		if c.PURL == "" {
			continue
		}
		helper := &piHelper{PURL: c.PURL}
		for algo, val := range c.Hashes {
			helper.Hashes = append(helper.Hashes, piHash{Algorithm: algo, Value: val})
		}
		versionBranch := branch{
			Category: "product_version",
			Name:     c.Version,
			Product: &product{
				Name:      c.Name + "@" + c.Version,
				ProductID: c.PURL,
				PIHelper:  helper,
			},
		}
		productBranch := branch{
			Category: "product_name",
			Name:     c.Name,
			Branches: []branch{versionBranch},
		}
		productBranches = append(productBranches, productBranch)
	}
	return productTree{
		Branches: []branch{{Category: "vendor", Name: publisherName, Branches: productBranches}},
	}
}
