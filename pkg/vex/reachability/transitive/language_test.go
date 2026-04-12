// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package transitive

import (
	"strings"
	"testing"
)

func TestLanguageFor_RegisteredLanguages(t *testing.T) {
	tests := []struct {
		input      string
		wantName   string
		wantEcosys string
	}{
		{"python", "python", "pypi"},
		{"Python", "python", "pypi"},
		{"PYTHON", "python", "pypi"},
		{"javascript", "javascript", "npm"},
		{"JavaScript", "javascript", "npm"},
		{"JAVASCRIPT", "javascript", "npm"},
		{"js", "javascript", "npm"},
		{"JS", "javascript", "npm"},
		{"rust", "rust", "crates.io"},
		{"Rust", "rust", "crates.io"},
		{"RUST", "rust", "crates.io"},
		{"ruby", "ruby", "rubygems"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			lang, err := LanguageFor(tc.input)
			if err != nil {
				t.Fatalf("LanguageFor(%q) returned error: %v", tc.input, err)
			}
			if lang == nil {
				t.Fatalf("LanguageFor(%q) returned nil without error", tc.input)
			}
			if lang.Name() != tc.wantName {
				t.Errorf("Name() = %q, want %q", lang.Name(), tc.wantName)
			}
			if lang.Ecosystem() != tc.wantEcosys {
				t.Errorf("Ecosystem() = %q, want %q", lang.Ecosystem(), tc.wantEcosys)
			}
		})
	}
}

func TestLanguageFor_UnknownLanguage(t *testing.T) {
	tests := []struct {
		input string
	}{
		{""},
		{"c++"},
		{"go"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			lang, err := LanguageFor(tc.input)
			if err == nil {
				t.Errorf("LanguageFor(%q) = %+v, nil; want error", tc.input, lang)
			}
			if lang != nil {
				t.Errorf("LanguageFor(%q) returned non-nil %+v along with error", tc.input, lang)
			}
			if !strings.Contains(err.Error(), "unsupported") {
				t.Errorf("error message %q should contain 'unsupported'", err.Error())
			}
		})
	}
}

// TestLanguageSupport_Contract verifies that every registered language
// honors the interface contract: non-empty identity fields, non-nil
// tree-sitter plumbing, and round-trippable name via LanguageFor.
//
//nolint:gocognit,gocyclo // contract test: each sub-check is intentionally co-located for readability
func TestLanguageSupport_Contract(t *testing.T) {
	registered := []string{"python", "javascript", "rust", "ruby"}
	for _, name := range registered {
		t.Run(name, func(t *testing.T) {
			lang, err := LanguageFor(name)
			if err != nil {
				t.Fatalf("LanguageFor(%q): %v", name, err)
			}
			if lang.Name() == "" {
				t.Error("Name() is empty")
			}
			if lang.Ecosystem() == "" {
				t.Error("Ecosystem() is empty")
			}
			exts := lang.FileExtensions()
			if len(exts) == 0 {
				t.Error("FileExtensions() is empty")
			}
			for _, e := range exts {
				if !strings.HasPrefix(e, ".") {
					t.Errorf("FileExtensions() contains %q without leading dot", e)
				}
			}
			if lang.Grammar() == nil {
				t.Error("Grammar() returned nil")
			}
			if lang.Extractor() == nil {
				t.Error("Extractor() returned nil")
			}
			// Round-trip: LanguageFor(lang.Name()) should return a language
			// with the same Name and Ecosystem.
			other, err := LanguageFor(lang.Name())
			if err != nil {
				t.Fatalf("round-trip LanguageFor(%q): %v", lang.Name(), err)
			}
			if other.Name() != lang.Name() {
				t.Errorf("round-trip Name: got %q, want %q", other.Name(), lang.Name())
			}
			if other.Ecosystem() != lang.Ecosystem() {
				t.Errorf("round-trip Ecosystem: got %q, want %q", other.Ecosystem(), lang.Ecosystem())
			}
		})
	}
}
