// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"testing"
)

//nolint:gocognit // table-driven test with many cases
func TestNormalizeRepoURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"https passthrough", "https://github.com/google/gson", "https://github.com/google/gson", false},
		{"strip .git suffix", "https://github.com/google/gson.git", "https://github.com/google/gson", false},
		{"git:// to https://", "git://github.com/google/gson.git", "https://github.com/google/gson", false},
		{"reject ssh", "git@github.com:google/gson.git", "", true},
		{"reject empty", "", "", true},
		{"http passthrough", "http://github.com/google/gson", "http://github.com/google/gson", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeRepoURL(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("normalizeRepoURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestVersionTags(t *testing.T) {
	tags := versionTags("1.2.3")
	expected := []string{"v1.2.3", "1.2.3", "release-1.2.3", "release/1.2.3"}
	if len(tags) != len(expected) {
		t.Fatalf("versionTags(\"1.2.3\") = %v, want %v", tags, expected)
	}
	for i, tag := range tags {
		if tag != expected[i] {
			t.Errorf("tag[%d] = %q, want %q", i, tag, expected[i])
		}
	}
}
