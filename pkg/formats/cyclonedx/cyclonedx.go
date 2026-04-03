package cyclonedx

import (
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
)

type Parser struct{}

//nolint:gocognit // CycloneDX component extraction requires nested traversal
func (p Parser) Parse(r io.Reader) ([]formats.Component, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}

	var components []formats.Component
	if bom.Components != nil {
		comps := *bom.Components
		components = make([]formats.Component, 0, len(comps))
		for i := range comps {
			comp := convertComponent(&comps[i])
			components = append(components, comp)
			if comps[i].Components != nil {
				components = append(components, flattenCDXComponents(*comps[i].Components)...)
			}
		}
	}
	return components, nil
}

// convertComponent converts a CycloneDX component to a formats.Component.
func convertComponent(c *cdx.Component) formats.Component {
	comp := formats.Component{
		Name:    c.Name,
		Version: c.Version,
		PURL:    c.PackageURL,
	}
	if c.PackageURL != "" {
		if purl, err := packageurl.FromString(c.PackageURL); err == nil {
			comp.Type = purl.Type
			comp.Namespace = purl.Namespace
			qualMap := purl.Qualifiers.Map()
			comp.Platform = qualMap["os"]
			comp.Arch = qualMap["arch"]
		}
	}
	if c.Hashes != nil {
		comp.Hashes = make(map[string]string)
		for _, h := range *c.Hashes {
			comp.Hashes[string(h.Algorithm)] = h.Value
		}
	}
	if c.Supplier != nil {
		comp.Supplier = c.Supplier.Name
	}
	return comp
}

func flattenCDXComponents(cdxComponents []cdx.Component) []formats.Component {
	result := make([]formats.Component, 0, len(cdxComponents))
	for i := range cdxComponents {
		result = append(result, convertComponent(&cdxComponents[i]))
		if cdxComponents[i].Components != nil {
			result = append(result, flattenCDXComponents(*cdxComponents[i].Components)...)
		}
	}
	return result
}
