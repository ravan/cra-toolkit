// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"
)

func TestDigest_String(t *testing.T) {
	d := Digest{Algorithm: "sha256", Hex: "abc"}
	if d.String() != "sha256:abc" {
		t.Errorf("got %q", d.String())
	}
}

func TestDigest_Equals(t *testing.T) {
	a := Digest{Algorithm: "sha256", Hex: "ABC"}
	b := Digest{Algorithm: "SHA256", Hex: "abc"}
	if !a.Equals(b) {
		t.Errorf("digests should be equal (case-insensitive)")
	}
}

func TestFetchResult_SourceUnavailable(t *testing.T) {
	r := FetchResult{SourceUnavailable: true}
	if !r.SourceUnavailable {
		t.Error("expected SourceUnavailable true")
	}
}

func TestPackageManifest_Dependencies(t *testing.T) {
	m := PackageManifest{
		Dependencies: map[string]string{
			"requests": ">=2.0",
			"urllib3":  "1.26.5",
		},
	}
	if len(m.Dependencies) != 2 {
		t.Errorf("expected 2 deps, got %d", len(m.Dependencies))
	}
}
