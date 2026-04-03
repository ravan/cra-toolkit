package cli

import (
	"context"
	"fmt"

	urfave "github.com/urfave/cli/v3"
)

func newVersionCmd(version string) *urfave.Command {
	return &urfave.Command{
		Name:  "version",
		Usage: "Print version information",
		Action: func(_ context.Context, cmd *urfave.Command) error {
			format := cmd.String("format")
			if format == "json" {
				fmt.Fprintf(cmd.Root().Writer, "{\"version\":%q}\n", version)
			} else {
				fmt.Fprintf(cmd.Root().Writer, "cra version %s\n", version)
			}
			return nil
		},
	}
}
