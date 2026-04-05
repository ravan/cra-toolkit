// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package spdx

import (
	"io"

	packageurl "github.com/package-url/packageurl-go"
	spdxjson "github.com/spdx/tools-golang/json"

	"github.com/ravan/cra-toolkit/pkg/formats"
)

type Parser struct{}

func (p Parser) Parse(r io.Reader) ([]formats.Component, error) {
	doc, err := spdxjson.Read(r)
	if err != nil {
		return nil, err
	}

	components := make([]formats.Component, 0, len(doc.Packages))
	for _, pkg := range doc.Packages {
		comp := formats.Component{
			Name:    pkg.PackageName,
			Version: pkg.PackageVersion,
		}

		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == "purl" {
				comp.PURL = ref.Locator
				if purl, err := packageurl.FromString(ref.Locator); err == nil {
					comp.Type = purl.Type
					comp.Namespace = purl.Namespace
					qualMap := purl.Qualifiers.Map()
					comp.Platform = qualMap["os"]
					comp.Arch = qualMap["arch"]
				}
				break
			}
		}

		if pkg.PackageSupplier != nil {
			comp.Supplier = pkg.PackageSupplier.Supplier
		}

		components = append(components, comp)
	}

	return components, nil
}
