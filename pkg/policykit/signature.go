// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package policykit

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// SignatureInfo describes a detected signature artifact.
type SignatureInfo struct {
	Path   string `json:"path"`
	Format string `json:"format"` // "cosign", "pgp", "x509", "unknown"
}

// cosignEnvelope is a minimal struct to detect cosign bundle mediaType.
type cosignEnvelope struct {
	MediaType string `json:"mediaType"`
}

// ParseSignature reads signature data and detects the format by probing content.
// It checks for cosign JSON bundles, PGP magic bytes/armor headers, and PEM headers.
func ParseSignature(r io.Reader, filename string) (*SignatureInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	format := detectSignatureFormat(data)

	return &SignatureInfo{
		Path:   filename,
		Format: format,
	}, nil
}

func detectSignatureFormat(data []byte) string {
	// Try cosign JSON bundle detection.
	if isCosignBundle(data) {
		return "cosign"
	}

	// Check for PGP binary magic bytes (0x89 = old format, 0xc0 = new format).
	if len(data) > 0 && (data[0] == 0x89 || data[0] == 0xc0) {
		return "pgp"
	}

	text := string(data)

	// Check for PGP ASCII armor.
	if strings.Contains(text, "-----BEGIN PGP") {
		return "pgp"
	}

	// Check for PEM/X.509 headers (but not PGP ones already caught above).
	if strings.Contains(text, "-----BEGIN ") {
		return "x509"
	}

	return "unknown"
}

func isCosignBundle(data []byte) bool {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return false
	}

	var env cosignEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return false
	}

	return strings.Contains(env.MediaType, "cosign")
}
