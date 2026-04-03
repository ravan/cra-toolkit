package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/vex"
)

func newVexCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "vex",
		Usage: "Determine VEX status for vulnerabilities against an SBOM",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return vex.Run()
		},
	}
}
