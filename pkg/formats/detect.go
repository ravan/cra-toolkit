// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package formats

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Format represents the detected format of an input file.
type Format int

const (
	FormatUnknown Format = iota
	FormatCycloneDX
	FormatSPDX
	FormatGrype
	FormatTrivy
	FormatSARIF
	FormatOpenVEX
	FormatCSAF
)

// String returns the name of the Format.
func (f Format) String() string {
	switch f {
	case FormatCycloneDX:
		return "CycloneDX"
	case FormatSPDX:
		return "SPDX"
	case FormatGrype:
		return "Grype"
	case FormatTrivy:
		return "Trivy"
	case FormatSARIF:
		return "SARIF"
	case FormatOpenVEX:
		return "OpenVEX"
	case FormatCSAF:
		return "CSAF"
	default:
		return "Unknown"
	}
}

// FormatProbe is a pluggable format detection rule.
// External modules register probes to support custom formats.
type FormatProbe struct {
	Format Format
	Detect func(doc map[string]json.RawMessage) bool
}

// DetectFormat reads JSON from r and detects which known format it belongs to.
// It probes for discriminating keys in the JSON structure.
//
//nolint:gocognit,gocyclo // sequential format probing inherently has many branches
func DetectFormat(r io.Reader, extraProbes ...FormatProbe) (Format, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return FormatUnknown, fmt.Errorf("detect format: read: %w", err)
	}

	// Decode into a generic map to probe keys
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return FormatUnknown, fmt.Errorf("detect format: parse JSON: %w", err)
	}

	// CycloneDX: has "bomFormat" key
	if _, ok := doc["bomFormat"]; ok {
		return FormatCycloneDX, nil
	}

	// SPDX: has "spdxVersion" key
	if _, ok := doc["spdxVersion"]; ok {
		return FormatSPDX, nil
	}

	// SARIF: "$schema" contains "sarif"
	if raw, ok := doc["$schema"]; ok {
		var schema string
		if err := json.Unmarshal(raw, &schema); err == nil {
			if strings.Contains(strings.ToLower(schema), "sarif") {
				return FormatSARIF, nil
			}
		}
	}

	// OpenVEX: "@context" contains "openvex"
	if raw, ok := doc["@context"]; ok {
		var ctx string
		if err := json.Unmarshal(raw, &ctx); err == nil {
			if strings.Contains(strings.ToLower(ctx), "openvex") {
				return FormatOpenVEX, nil
			}
		}
	}

	// CSAF: "document.category" contains "csaf"
	if raw, ok := doc["document"]; ok {
		var docMeta map[string]json.RawMessage
		if err := json.Unmarshal(raw, &docMeta); err == nil {
			if catRaw, ok := docMeta["category"]; ok {
				var category string
				if err := json.Unmarshal(catRaw, &category); err == nil {
					if strings.Contains(strings.ToLower(category), "csaf") {
						return FormatCSAF, nil
					}
				}
			}
		}
	}

	// Grype: has "matches" key
	if _, ok := doc["matches"]; ok {
		return FormatGrype, nil
	}

	// Trivy: has "Results" key (capital R is the standard Trivy output)
	if _, ok := doc["Results"]; ok {
		return FormatTrivy, nil
	}

	// Extension probes (checked after all built-in probes).
	for _, probe := range extraProbes {
		if probe.Detect(doc) {
			return probe.Format, nil
		}
	}

	return FormatUnknown, nil
}
