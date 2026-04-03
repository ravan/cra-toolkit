package reachability

import (
	"os"
	"path/filepath"
)

// languageMarkers maps language names to the filenames that indicate their presence.
var languageMarkers = map[string][]string{
	"go":         {"go.mod"},
	"rust":       {"Cargo.toml"},
	"javascript": {"package.json"},
	"python":     {"requirements.txt", "pyproject.toml", "setup.py"},
	"java":       {"pom.xml", "build.gradle", "build.gradle.kts"},
}

// DetectLanguages inspects the given directory and returns the set of
// programming languages found, based on the presence of known manifest files.
func DetectLanguages(dir string) []string {
	var langs []string
	for lang, markers := range languageMarkers {
		for _, marker := range markers {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				langs = append(langs, lang)
				break
			}
		}
	}
	return langs
}
