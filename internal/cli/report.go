package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/report"
)

func newReportCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "report",
		Usage: "Generate CRA Article 14 vulnerability notification documents",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return report.Run()
		},
	}
}
