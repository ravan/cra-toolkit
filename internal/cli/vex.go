// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/vex"
)

func newVexCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "vex",
		Usage: "Determine VEX status for vulnerabilities against an SBOM",
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
			&urfave.StringSliceFlag{
				Name:  "upstream-vex",
				Usage: "path to upstream VEX document (OpenVEX or CSAF); repeatable",
			},
			&urfave.StringFlag{
				Name:  "source-dir",
				Usage: "path to source code for reachability analysis",
			},
			&urfave.StringFlag{
				Name:  "output-format",
				Value: "openvex",
				Usage: "output format: openvex or csaf",
			},
		},
		Action: func(_ context.Context, cmd *urfave.Command) error {
			outputFormat := cmd.String("output-format")
			if outputFormat != "openvex" && outputFormat != "csaf" {
				return fmt.Errorf("unsupported output format %q: must be openvex or csaf", outputFormat)
			}

			opts := &vex.Options{
				SBOMPath:         cmd.String("sbom"),
				ScanPaths:        cmd.StringSlice("scan"),
				UpstreamVEXPaths: cmd.StringSlice("upstream-vex"),
				SourceDir:        cmd.String("source-dir"),
				OutputFormat:     outputFormat,
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // closer returns nil for stdout

			return vex.Run(opts, w)
		},
	}
}
