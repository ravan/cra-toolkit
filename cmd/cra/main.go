package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ravan/suse-cra-toolkit/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cmd := cli.New(version)
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
