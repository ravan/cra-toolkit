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

func newVexCmd(cfg *RunConfig) *urfave.Command {
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
			&urfave.BoolFlag{
				Name:  "transitive",
				Usage: "enable transitive dependency reachability analysis (Python, JavaScript)",
				Value: true,
			},
			&urfave.StringFlag{
				Name:  "transitive-cache-dir",
				Usage: "cache directory for fetched package tarballs (default ~/.cache/cra-toolkit/pkgs)",
			},
		},
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			outputFormat := cmd.String("output-format")
			if !hasVEXWriter(outputFormat, cfg.ExtraVEXWriters) {
				return fmt.Errorf("unsupported output format %q", outputFormat)
			}

			opts := &vex.Options{
				SBOMPath:           cmd.String("sbom"),
				ScanPaths:          cmd.StringSlice("scan"),
				UpstreamVEXPaths:   cmd.StringSlice("upstream-vex"),
				SourceDir:          cmd.String("source-dir"),
				OutputFormat:       outputFormat,
				TransitiveEnabled:  cmd.Bool("transitive"),
				TransitiveCacheDir: cmd.String("transitive-cache-dir"),
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // closer returns nil for stdout

			runOpts := buildVexRunOpts(cfg)
			hooks := buildHooks(cfg, "vex")
			return toolkit.ExecuteWithHooks(ctx, "vex", hooks, opts, func() error {
				return vex.Run(opts, w, runOpts...)
			})
		},
	}
}

// buildVexRunOpts converts RunConfig extension registrations into vex.RunOption values.
func buildVexRunOpts(cfg *RunConfig) []vex.RunOption {
	var opts []vex.RunOption
	if len(cfg.ExtraFilters) > 0 {
		opts = append(opts, vex.WithExtraFilters(cfg.ExtraFilters))
	}
	if len(cfg.ExtraAnalyzers) > 0 {
		opts = append(opts, vex.WithExtraAnalyzers(cfg.ExtraAnalyzers))
	}
	if len(cfg.ExtraScanParsers) > 0 {
		opts = append(opts, vex.WithExtraScanParsers(cfg.ExtraScanParsers))
	}
	if len(cfg.ExtraSBOMParsers) > 0 {
		opts = append(opts, vex.WithExtraSBOMParsers(cfg.ExtraSBOMParsers))
	}
	if len(cfg.ExtraVEXWriters) > 0 {
		opts = append(opts, vex.WithExtraVEXWriters(cfg.ExtraVEXWriters))
	}
	if len(cfg.ExtraFormatProbes) > 0 {
		opts = append(opts, vex.WithExtraFormatProbes(cfg.ExtraFormatProbes))
	}
	return opts
}

func hasVEXWriter(format string, extra map[string]formats.VEXWriter) bool {
	if format == "openvex" || format == "csaf" {
		return true
	}
	_, ok := extra[format]
	return ok
}
