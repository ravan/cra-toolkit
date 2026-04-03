package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
)

func newPolicykitCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "policykit",
		Usage: "Evaluate CRA Annex I compliance policies against product artifacts",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return policykit.Run()
		},
	}
}
