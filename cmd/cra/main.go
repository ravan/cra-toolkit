package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ravan/suse-cra-toolkit/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown" //nolint:unused // set via -ldflags at build time
	date    = "unknown" //nolint:unused // set via -ldflags at build time
)

func main() {
	cmd := cli.New(version)
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
