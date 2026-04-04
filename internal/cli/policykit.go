package cli

import (
	"context"
	"os"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
)

func newPolicykitCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "policykit",
		Usage: "Evaluate CRA Annex I compliance policies against product artifacts",
		Action: func(_ context.Context, _ *urfave.Command) error {
			// TODO: wire CLI flags in Task 9
			return policykit.Run(&policykit.Options{}, os.Stdout)
		},
	}
}
