// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/csaf"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
)

func newCsafCmd(cfg RunConfig) *urfave.Command {
	return &urfave.Command{
		Name:  "csaf",
		Usage: "Generate CSAF 2.0 security advisories from scanner output and VEX assessments",
		Flags: []urfave.Flag{
			&urfave.StringFlag{
				Name:     "sbom",
				Usage:    "path to SBOM file (CycloneDX or SPDX)",
				Required: true,
			},
			&urfave.StringSliceFlag{
				Name:     "scan",
				Usage:    "path to scan results (Grype, Trivy, or SARIF); repeatable",
				Required: true,
			},
			&urfave.StringFlag{
				Name:  "vex",
				Usage: "path to VEX results (OpenVEX or CSAF VEX)",
			},
			&urfave.StringFlag{
				Name:     "publisher-name",
				Usage:    "organization name for the advisory publisher",
				Required: true,
			},
			&urfave.StringFlag{
				Name:     "publisher-namespace",
				Usage:    "organization URL for the advisory publisher",
				Required: true,
			},
			&urfave.StringFlag{
				Name:  "tracking-id",
				Usage: "advisory tracking ID (auto-generated if omitted)",
			},
			&urfave.StringFlag{
				Name:  "title",
				Usage: "advisory title (auto-generated if omitted)",
			},
		},
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			opts := &csaf.Options{
				SBOMPath:           cmd.String("sbom"),
				ScanPaths:          cmd.StringSlice("scan"),
				VEXPath:            cmd.String("vex"),
				PublisherName:      cmd.String("publisher-name"),
				PublisherNamespace: cmd.String("publisher-namespace"),
				TrackingID:         cmd.String("tracking-id"),
				Title:              cmd.String("title"),
			}
			if len(opts.ScanPaths) == 0 {
				return fmt.Errorf("at least one --scan path is required")
			}
			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // closer returns nil for stdout
			hooks := buildHooks(cfg, "csaf")
			return toolkit.ExecuteWithHooks(ctx, "csaf", hooks, opts, func() error {
				return csaf.Run(opts, w)
			})
		},
	}
}
