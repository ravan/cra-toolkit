// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/cra-toolkit/pkg/report"
	"github.com/ravan/cra-toolkit/pkg/toolkit"
)

func newReportCmd(cfg *RunConfig) *urfave.Command {
	return &urfave.Command{
		Name:  "report",
		Usage: "Generate CRA Article 14 vulnerability notification documents",
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
				Name:     "stage",
				Usage:    "notification stage: early-warning, notification, final-report",
				Required: true,
			},
			&urfave.StringFlag{
				Name:     "product-config",
				Usage:    "path to product config YAML with manufacturer section",
				Required: true,
			},
			&urfave.StringFlag{
				Name:  "kev",
				Usage: "path to local CISA KEV catalog JSON (auto-fetched if omitted)",
			},
			&urfave.StringFlag{
				Name:  "epss-path",
				Usage: "path to EPSS scores JSON (optional)",
			},
			&urfave.Float64Flag{
				Name:  "epss-threshold",
				Value: 0.7,
				Usage: "EPSS score threshold for exploitation signal (0.0-1.0)",
			},
			&urfave.StringFlag{
				Name:  "vex",
				Usage: "path to VEX results (OpenVEX or CSAF VEX)",
			},
			&urfave.StringFlag{
				Name:  "human-input",
				Usage: "path to human input YAML for 14-day final report",
			},
			&urfave.StringFlag{
				Name:  "csaf-advisory-ref",
				Usage: "companion CSAF advisory ID for Art. 14(8) user notification",
			},
			&urfave.StringFlag{
				Name:  "corrective-measure-date",
				Usage: "ISO 8601 date when corrective measure became available (Art. 14(2)(c))",
			},
			&urfave.StringFlag{
				Name:  "format",
				Value: "json",
				Usage: "output format: json or markdown",
			},
		},
		Action: func(ctx context.Context, cmd *urfave.Command) error {
			stage, err := report.ParseStage(cmd.String("stage"))
			if err != nil {
				return err
			}

			outputFormat := cmd.String("format")
			if outputFormat != "json" && outputFormat != "markdown" {
				return fmt.Errorf("unsupported format %q: must be json or markdown", outputFormat)
			}

			opts := &report.Options{
				SBOMPath:              cmd.String("sbom"),
				ScanPaths:             cmd.StringSlice("scan"),
				Stage:                 stage,
				ProductConfig:         cmd.String("product-config"),
				KEVPath:               cmd.String("kev"),
				EPSSPath:              cmd.String("epss-path"),
				EPSSThreshold:         cmd.Float64("epss-threshold"),
				VEXPath:               cmd.String("vex"),
				HumanInputPath:        cmd.String("human-input"),
				CSAFAdvisoryRef:       cmd.String("csaf-advisory-ref"),
				CorrectiveMeasureDate: cmd.String("corrective-measure-date"),
				OutputFormat:          outputFormat,
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // output writer close errors are non-actionable

			hooks := buildHooks(cfg, "report")
			return toolkit.ExecuteWithHooks(ctx, "report", hooks, opts, func() error {
				return report.Run(opts, w)
			})
		},
	}
}
