package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ParseEPSS reads EPSS JSON from r and returns parsed scores.
func ParseEPSS(r io.Reader) (*EPSSData, error) {
	var data EPSSData
	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, fmt.Errorf("parsing EPSS JSON: %w", err)
	}
	if data.Scores == nil {
		data.Scores = make(map[string]float64)
	}
	return &data, nil
}

// LoadEPSS loads EPSS data from a local file. Returns nil if path is empty.
func LoadEPSS(path string) (*EPSSData, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // nil means EPSS not provided
	}
	f, err := os.Open(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("opening EPSS file %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	return ParseEPSS(f)
}
