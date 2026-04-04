package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
)

func newPolicykitCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "policykit",
		Usage: "Evaluate CRA Annex I compliance policies against product artifacts",
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
				Name:     "vex",
				Usage:    "path to VEX document (OpenVEX or CSAF)",
				Required: true,
			},
			&urfave.StringFlag{
				Name:  "provenance",
				Usage: "path to SLSA provenance attestation JSON",
			},
			&urfave.StringSliceFlag{
				Name:  "signature",
				Usage: "path to signature file (repeatable)",
			},
			&urfave.StringFlag{
				Name:  "product-config",
				Usage: "path to product metadata YAML/JSON",
			},
			&urfave.StringFlag{
				Name:  "kev",
				Usage: "path to local CISA KEV catalog JSON (auto-fetched if omitted)",
			},
			&urfave.StringFlag{
				Name:  "policy-dir",
				Usage: "directory of custom Rego policies",
			},
			&urfave.StringFlag{
				Name:  "format",
				Value: "json",
				Usage: "output format: json or markdown",
			},
		},
		Action: func(_ context.Context, cmd *urfave.Command) error {
			outputFormat := cmd.String("format")
			if outputFormat != "json" && outputFormat != "markdown" {
				return fmt.Errorf("unsupported format %q: must be json or markdown", outputFormat)
			}

			opts := &policykit.Options{
				SBOMPath:       cmd.String("sbom"),
				ScanPaths:      cmd.StringSlice("scan"),
				VEXPath:        cmd.String("vex"),
				ProvenancePath: cmd.String("provenance"),
				SignaturePaths: cmd.StringSlice("signature"),
				ProductConfig:  cmd.String("product-config"),
				KEVPath:        cmd.String("kev"),
				PolicyDir:      cmd.String("policy-dir"),
				OutputFormat:   outputFormat,
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // output writer close errors are non-actionable at this point

			return policykit.Run(opts, w)
		},
	}
}
