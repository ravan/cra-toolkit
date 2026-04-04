package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/internal/cli"
)

func TestNew_ReturnsCommand(t *testing.T) {
	cmd := cli.New("1.0.0-test")
	if cmd == nil || cmd.Name != "cra" {
		t.Errorf("expected non-nil command with name 'cra', got %v", cmd)
	}
}

func TestNew_RegistersAllSubcommands(t *testing.T) {
	cmd := cli.New("1.0.0-test")

	expected := []string{"version", "vex", "policykit", "report", "evidence", "csaf"}
	registered := make(map[string]bool)
	for _, sub := range cmd.Commands {
		registered[sub.Name] = true
	}

	for _, name := range expected {
		if !registered[name] {
			t.Errorf("expected subcommand %q to be registered", name)
		}
	}
}

func TestVersionCmd_JSON(t *testing.T) {
	cmd := cli.New("1.2.3")
	var buf bytes.Buffer
	cmd.Writer = &buf

	err := cmd.Run(context.Background(), []string{"cra", "version"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"version"`) || !strings.Contains(out, "1.2.3") {
		t.Errorf("expected JSON version output containing 1.2.3, got %q", out)
	}
}

func TestVersionCmd_Text(t *testing.T) {
	cmd := cli.New("1.2.3")
	var buf bytes.Buffer
	cmd.Writer = &buf

	err := cmd.Run(context.Background(), []string{"cra", "--format", "text", "version"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "cra version 1.2.3") {
		t.Errorf("expected text version output, got %q", out)
	}
}

func TestSubcommandStubs_ReturnNotImplemented(t *testing.T) {
	// evidence is still a stub; report is fully implemented (required flags guard it).
	subcmds := []string{"evidence"}
	for _, name := range subcmds {
		t.Run(name, func(t *testing.T) {
			cmd := cli.New("test")
			err := cmd.Run(context.Background(), []string{"cra", name})
			if err == nil {
				t.Errorf("expected error from stub subcommand %q, got nil", name)
			}
			if err != nil && !strings.Contains(err.Error(), "not implemented") {
				t.Errorf("expected 'not implemented' error, got %q", err.Error())
			}
		})
	}
}

func TestReportCmd_RequiredFlagsEnforced(t *testing.T) {
	cmd := cli.New("test")
	err := cmd.Run(context.Background(), []string{"cra", "report"})
	if err == nil {
		t.Fatal("expected error when required flags are missing, got nil")
	}
	// urfave/cli v3 reports missing required flags — not "not implemented".
	if strings.Contains(err.Error(), "not implemented") {
		t.Errorf("report command should not return 'not implemented'; got %q", err.Error())
	}
}
