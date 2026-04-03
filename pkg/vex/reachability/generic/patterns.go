package generic

// pypiToImport maps common PyPI package names to their Python import names.
var pypiToImport = map[string]string{
	"PyYAML":          "yaml",
	"Pillow":          "PIL",
	"scikit-learn":    "sklearn",
	"beautifulsoup4":  "bs4",
	"python-dateutil": "dateutil",
	"msgpack-python":  "msgpack",
	"attrs":           "attr",
	"pycryptodome":    "Crypto",
}

// NormalizeModuleName converts a package name to its import name for the given language.
func NormalizeModuleName(name, language string) string {
	if language == "python" {
		if importName, ok := pypiToImport[name]; ok {
			return importName
		}
	}
	return name
}

// importPatterns returns regex patterns for detecting imports of the given module
// in the specified language. Returns (patterns, glob).
func importPatterns(module, language string) (patterns []string, glob string) {
	switch language {
	case "python":
		return []string{
			`import\s+` + module,
			`from\s+` + module + `\s+import`,
		}, "*.py"
	case "javascript":
		return []string{
			`require\(\s*['"]` + module + `['"]\s*\)`,
			`from\s+['"]` + module + `['"]`,
		}, "*.{js,ts,jsx,tsx,mjs,cjs}"
	case "java":
		return []string{
			`import\s+` + module,
		}, "*.java"
	default:
		return []string{
			module,
		}, "*"
	}
}
