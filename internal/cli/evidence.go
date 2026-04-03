package cli

import (
	"context"

	urfave "github.com/urfave/cli/v3"

	"github.com/ravan/suse-cra-toolkit/pkg/evidence"
)

func newEvidenceCmd() *urfave.Command {
	return &urfave.Command{
		Name:  "evidence",
		Usage: "Bundle compliance outputs into a signed CRA evidence package",
		Action: func(_ context.Context, _ *urfave.Command) error {
			return evidence.Run()
		},
	}
}
