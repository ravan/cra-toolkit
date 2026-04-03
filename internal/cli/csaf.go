package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/csaf"
)

func newCsafCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "csaf",
		Usage: "Convert scanner output and VEX into CSAF 2.0 advisories",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return csaf.Run()
		},
	}
}
