// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

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
				_, err := fmt.Fprintf(cmd.Root().Writer, "{\"version\":%q}\n", version)
				return err
			}
			_, err := fmt.Fprintf(cmd.Root().Writer, "cra version %s\n", version)
			return err
		},
	}
}
