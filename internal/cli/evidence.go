// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
)

func newEvidenceCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "evidence",
		Usage: "Bundle compliance outputs into a signed CRA evidence package for Annex VII",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "sbom", Usage: "Path to SBOM (CycloneDX or SPDX)"},
			&urfave.StringFlag{Name: "vex", Usage: "Path to VEX document (OpenVEX or CSAF)"},
			&urfave.StringSliceFlag{Name: "scan", Usage: "Path to scan results (Grype/Trivy/SARIF), repeatable"},
			&urfave.StringFlag{Name: "policy-report", Usage: "Path to cra-policykit report (JSON)"},
			&urfave.StringFlag{Name: "csaf", Usage: "Path to CSAF advisory"},
			&urfave.StringFlag{Name: "art14-report", Usage: "Path to Art. 14 notification (JSON)"},
			&urfave.StringFlag{Name: "risk-assessment", Usage: "Path to cybersecurity risk assessment document"},
			&urfave.StringFlag{Name: "architecture", Usage: "Path to design/development architecture document"},
			&urfave.StringFlag{Name: "production-process", Usage: "Path to production/monitoring process document"},
			&urfave.StringFlag{Name: "eu-declaration", Usage: "Path to EU declaration of conformity"},
			&urfave.StringFlag{Name: "cvd-policy", Usage: "Path to coordinated vulnerability disclosure policy"},
			&urfave.StringFlag{Name: "standards", Usage: "Path to harmonised standards document"},
			&urfave.StringFlag{Name: "product-config", Required: true, Usage: "Path to product configuration (YAML)"},
			&urfave.StringFlag{Name: "output-dir", Required: true, Usage: "Output directory for evidence bundle"},
			&urfave.StringFlag{Name: "format", Value: "json", Usage: "Output format: json, markdown"},
			&urfave.BoolFlag{Name: "archive", Usage: "Also produce .tar.gz archive"},
			&urfave.StringFlag{Name: "signing-key", Usage: "Cosign key path (keyless if omitted)"},
		},
		Action: func(_ context.Context, cmd *urfave.Command) error {
			opts := &evidence.Options{
				SBOMPath:          cmd.String("sbom"),
				VEXPath:           cmd.String("vex"),
				ScanPaths:         cmd.StringSlice("scan"),
				PolicyReport:      cmd.String("policy-report"),
				CSAFPath:          cmd.String("csaf"),
				ReportPath:        cmd.String("art14-report"),
				RiskAssessment:    cmd.String("risk-assessment"),
				ArchitectureDocs:  cmd.String("architecture"),
				ProductionProcess: cmd.String("production-process"),
				EUDeclaration:     cmd.String("eu-declaration"),
				CVDPolicy:         cmd.String("cvd-policy"),
				StandardsDoc:      cmd.String("standards"),
				ProductConfig:     cmd.String("product-config"),
				OutputDir:         cmd.String("output-dir"),
				OutputFormat:      cmd.String("format"),
				Archive:           cmd.Bool("archive"),
				SigningKey:        cmd.String("signing-key"),
			}

			w, closer := OutputWriter(cmd)
			defer closer() //nolint:errcheck // CLI cleanup

			return evidence.Run(opts, w)
		},
	}
}
