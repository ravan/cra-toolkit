package cli

import (
	"io"
	"os"

	urfave "github.com/urfave/cli/v3"
)

// New creates the root CRA CLI command with all global flags and subcommands registered.
func New(version string) *urfave.Command {
	return &urfave.Command{
		Name:    "cra",
		Usage:   "SUSE CRA Compliance Toolkit",
		Version: version,
		Flags: []urfave.Flag{
			&urfave.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Value:   "json",
				Usage:   "output format: json or text",
			},
			&urfave.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "output file path (default: stdout)",
			},
			&urfave.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "suppress non-essential output",
			},
			&urfave.BoolFlag{
				Name:  "verbose",
				Usage: "enable debug logging",
			},
		},
		Commands: []*urfave.Command{
			newVersionCmd(version),
			newVexCmd(),
			newPolicykitCmd(),
			newReportCmd(),
			newEvidenceCmd(),
			newCsafCmd(),
		},
	}
}

// OutputWriter returns the appropriate writer based on the --output flag.
func OutputWriter(cmd *urfave.Command) (w io.Writer, closer func() error) {
	path := cmd.String("output")
	if path == "" {
		return os.Stdout, func() error { return nil }
	}

	f, err := os.Create(path) //nolint:gosec // path is from CLI flag, user-controlled by design
	if err != nil {
		return os.Stdout, func() error { return nil }
	}

	return f, f.Close
}
