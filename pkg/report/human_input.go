package report

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadHumanInput loads human-authored vulnerability data for the 14-day final report.
// Returns nil if path is empty.
func LoadHumanInput(path string) (*HumanInput, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // nil means no human input provided
	}

	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("reading human input %s: %w", path, err)
	}

	var hi HumanInput
	if err := yaml.Unmarshal(data, &hi); err != nil {
		return nil, fmt.Errorf("parsing human input %s: %w", path, err)
	}

	return &hi, nil
}
