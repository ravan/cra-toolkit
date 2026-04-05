// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadReportConfig loads and validates the extended product config with manufacturer section.
func LoadReportConfig(path string) (*ReportProductConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CLI flag
	if err != nil {
		return nil, fmt.Errorf("reading product config %s: %w", path, err)
	}

	var cfg ReportProductConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing product config %s: %w", path, err)
	}

	if cfg.Manufacturer.Name == "" {
		return nil, fmt.Errorf("product config %s: manufacturer.name is required", path)
	}
	if cfg.Manufacturer.MemberState == "" {
		return nil, fmt.Errorf("product config %s: manufacturer.member_state is required", path)
	}

	return &cfg, nil
}
