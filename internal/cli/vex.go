// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/formats"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
	"github.com/ravan/cra-toolkit/pkg/vex"
)

func newVexCmd(cfg RunConfig) *urfave.Command {
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
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			outputFormat := cmd.String("output-format")
			if !hasVEXWriter(outputFormat, cfg.ExtraVEXWriters) {
				return fmt.Errorf("unsupported output format %q", outputFormat)
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

			// Build RunOptions from config.
			var runOpts []vex.RunOption
			if len(cfg.ExtraFilters) > 0 {
				runOpts = append(runOpts, vex.WithExtraFilters(cfg.ExtraFilters))
			}
			if len(cfg.ExtraAnalyzers) > 0 {
				runOpts = append(runOpts, vex.WithExtraAnalyzers(cfg.ExtraAnalyzers))
			}
			if len(cfg.ExtraScanParsers) > 0 {
				runOpts = append(runOpts, vex.WithExtraScanParsers(cfg.ExtraScanParsers))
			}
			if len(cfg.ExtraSBOMParsers) > 0 {
				runOpts = append(runOpts, vex.WithExtraSBOMParsers(cfg.ExtraSBOMParsers))
			}
			if len(cfg.ExtraVEXWriters) > 0 {
				runOpts = append(runOpts, vex.WithExtraVEXWriters(cfg.ExtraVEXWriters))
			}
			if len(cfg.ExtraFormatProbes) > 0 {
				runOpts = append(runOpts, vex.WithExtraFormatProbes(cfg.ExtraFormatProbes))
			}

			hooks := buildHooks(cfg, "vex")
			return toolkit.ExecuteWithHooks(ctx, "vex", hooks, opts, func() error {
				return vex.Run(opts, w, runOpts...)
			})
		},
	}
}

func hasVEXWriter(format string, extra map[string]formats.VEXWriter) bool {
	if format == "openvex" || format == "csaf" {
		return true
	}
	_, ok := extra[format]
	return ok
}
