// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cyclonedx

import (
	"io"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"

	"github.com/ravan/cra-toolkit/pkg/formats"
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

// ParseDirectDeps returns the names of packages listed as direct dependencies
// of the application component in a CycloneDX SBOM's dependencies block.
// Returns nil when the file cannot be read, is not valid CycloneDX, or the
// metadata component has no dependsOn entry.
func ParseDirectDeps(path string) []string {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	bom := new(cdx.BOM)
	if err := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return nil
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return nil
	}
	appRef := bom.Metadata.Component.BOMRef
	if appRef == "" || bom.Dependencies == nil {
		return nil
	}

	// Build bom-ref → name map for components that carry a BOMRef.
	refToName := make(map[string]string)
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.BOMRef != "" {
				refToName[c.BOMRef] = c.Name
			}
		}
	}

	for _, dep := range *bom.Dependencies {
		if dep.Ref != appRef || dep.Dependencies == nil {
			continue
		}
		var names []string
		for _, childRef := range *dep.Dependencies {
			if n := resolveRefName(childRef, refToName); n != "" {
				names = append(names, n)
			}
		}
		return names
	}
	return nil
}

// resolveRefName resolves a CycloneDX dependency ref to a package name.
// It first checks the bom-ref map, then falls back to PURL name extraction.
// Handles Syft-style qualifiers: "pkg:pypi/requests@2.31.0?package-id=xxx" → "requests".
func resolveRefName(ref string, refToName map[string]string) string {
	if n, ok := refToName[ref]; ok {
		return n
	}
	// PURL extraction: "pkg:<type>/<name>@<version>[?qualifiers]"
	if purl, err := packageurl.FromString(ref); err == nil {
		return purl.Name
	}
	return ""
}
