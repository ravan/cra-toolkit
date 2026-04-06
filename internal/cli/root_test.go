// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ravan/cra-toolkit/internal/cli"
)

func TestNew_ReturnsCommand(t *testing.T) {
	cmd := cli.New("1.0.0-test", cli.RunConfig{})
	if cmd == nil || cmd.Name != "cra" {
		t.Errorf("expected non-nil command with name 'cra', got %v", cmd)
	}
}

func TestNew_RegistersAllSubcommands(t *testing.T) {
	cmd := cli.New("1.0.0-test", cli.RunConfig{})

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
	cmd := cli.New("1.2.3", cli.RunConfig{})
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
	cmd := cli.New("1.2.3", cli.RunConfig{})
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

func TestEvidenceCmd_RequiredFlagsEnforced(t *testing.T) {
	cmd := cli.New("test", cli.RunConfig{})
	err := cmd.Run(context.Background(), []string{"cra", "evidence"})
	if err == nil {
		t.Fatal("expected error when required flags are missing, got nil")
	}
	// urfave/cli v3 reports missing required flags — not "not implemented".
	if strings.Contains(err.Error(), "not implemented") {
		t.Errorf("evidence command should not return 'not implemented'; got %q", err.Error())
	}
}

func TestReportCmd_RequiredFlagsEnforced(t *testing.T) {
	cmd := cli.New("test", cli.RunConfig{})
	err := cmd.Run(context.Background(), []string{"cra", "report"})
	if err == nil {
		t.Fatal("expected error when required flags are missing, got nil")
	}
	// urfave/cli v3 reports missing required flags — not "not implemented".
	if strings.Contains(err.Error(), "not implemented") {
		t.Errorf("report command should not return 'not implemented'; got %q", err.Error())
	}
}
