// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package reachability

import (
	"os"
	"path/filepath"
	"strings"
)

// languageMarkers maps language names to the filenames that indicate their presence.
// Values may be exact filenames or glob patterns (containing "*").
var languageMarkers = map[string][]string{
	"go":         {"go.mod"},
	"rust":       {"Cargo.toml"},
	"javascript": {"package.json"},
	"python":     {"requirements.txt", "pyproject.toml", "setup.py"},
	"java":       {"pom.xml", "build.gradle", "build.gradle.kts"},
	"csharp":     {"*.csproj", "*.sln"},
	"php":        {"composer.json"},
	"ruby":       {"Gemfile"},
}

// DetectLanguages inspects the given directory and returns the set of
// programming languages found, based on the presence of known manifest files.
//
//nolint:gocognit // marker detection branches on glob vs exact match for each language
func DetectLanguages(dir string) []string {
	var langs []string
	for lang, markers := range languageMarkers {
		if markerPresent(dir, markers) {
			langs = append(langs, lang)
		}
	}
	return langs
}

// markerPresent returns true if any of the given markers is found in dir.
// Markers may be exact filenames or glob patterns (containing "*").
func markerPresent(dir string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(marker, "*") {
			matches, _ := filepath.Glob(filepath.Join(dir, marker))
			if len(matches) > 0 {
				return true
			}
		} else {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return true
			}
		}
	}
	return false
}
