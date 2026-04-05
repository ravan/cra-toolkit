// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

//go:build llmjudge

package report_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/report"
)

type reportLLMScores struct {
	RegulatoryAccuracy      int    `json:"regulatory_accuracy"`
	SignalTransparency      int    `json:"signal_transparency"`
	SubmissionHonesty       int    `json:"submission_honesty"`
	DeadlineAccuracy        int    `json:"deadline_accuracy"`
	UserNotificationQuality int    `json:"user_notification_quality"`
	OverallQuality          int    `json:"overall_quality"`
	Reasoning               string `json:"reasoning"`
}

func TestLLMJudge_ReportKEVNotification(t *testing.T) {
	geminiPath, err := exec.LookPath("gemini")
	if err != nil {
		t.Skip("gemini CLI not available, skipping LLM judge test")
	}

	dir := filepath.Join(fixtureBase, "report-kev-early-warning")
	opts := &report.Options{
		SBOMPath:      filepath.Join(dir, "sbom.cdx.json"),
		ScanPaths:     []string{filepath.Join(dir, "grype.json")},
		Stage:         report.StageNotification,
		ProductConfig: filepath.Join(dir, "product-config.yaml"),
		KEVPath:       filepath.Join(dir, "kev.json"),
		OutputFormat:  "json",
	}

	var buf bytes.Buffer
	if err := report.Run(opts, &buf); err != nil {
		t.Fatalf("report.Run() error: %v", err)
	}

	reportFile, err := os.CreateTemp(".", "report-generated-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(reportFile.Name()) //nolint:errcheck // test cleanup
	if _, err := reportFile.Write(buf.Bytes()); err != nil {
		t.Fatalf("write report: %v", err)
	}
	reportFile.Close()

	prompt := fmt.Sprintf(`You are a CRA (EU Cyber Resilience Act) Article 14 notification quality judge.

CRA Article 14 requires manufacturers to notify actively exploited vulnerabilities:
- Art. 14(1): Notify CSIRT and ENISA simultaneously via Single Reporting Platform
- Art. 14(2)(a): 24h early warning with CVE, severity, affected products, member states
- Art. 14(2)(b): 72h notification with description, exploit nature, corrective actions, sensitivity
- Art. 14(2)(c): 14-day final report (after corrective measure available) with root cause, threat actor, security update
- Art. 14(7): Submit via ENISA Single Reporting Platform, routed to Member State CSIRT
- Art. 14(8): Inform users in structured, machine-readable format

IMPORTANT: The tool should aggregate exploitation SIGNALS to support the manufacturer's determination.
It should NOT claim to make the regulatory determination itself. The submission channel should be
ENISA SRP, not direct CSIRT contact.

Read the GENERATED NOTIFICATION from: %s

Score on these dimensions (1-10 each):
1. regulatory_accuracy: Do fields map correctly to Art. 14(2) required content? Tool does not overstate its role?
2. signal_transparency: Are exploitation signals clearly labeled with source and confidence?
3. submission_honesty: Does output correctly identify ENISA SRP as submission channel, not direct CSIRT?
4. deadline_accuracy: Are deadline references correct per Art. 14(2)(a-c)?
5. user_notification_quality: Is Art. 14(8) section actionable for downstream users?
6. overall_quality: Would a compliance officer trust this for ENISA SRP submission?

Respond ONLY with valid JSON, no other text:
{"regulatory_accuracy": N, "signal_transparency": N, "submission_honesty": N, "deadline_accuracy": N, "user_notification_quality": N, "overall_quality": N, "reasoning": "brief explanation"}`,
		reportFile.Name())

	cmd := exec.Command(geminiPath, "--approval-mode", "plan", "-p", prompt) //nolint:gosec
	var geminiOut bytes.Buffer
	cmd.Stdout = &geminiOut
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gemini error: %v", err)
	}

	responseText := geminiOut.String()
	jsonStart := strings.Index(responseText, "{")
	jsonEnd := strings.LastIndex(responseText, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		t.Fatalf("no JSON in response: %s", responseText)
	}

	var scores reportLLMScores
	if err := json.Unmarshal([]byte(responseText[jsonStart:jsonEnd+1]), &scores); err != nil {
		t.Fatalf("parse scores: %v\nresponse: %s", err, responseText)
	}

	t.Logf("LLM Scores: regulatory=%d signals=%d submission=%d deadline=%d user_notif=%d overall=%d",
		scores.RegulatoryAccuracy, scores.SignalTransparency, scores.SubmissionHonesty,
		scores.DeadlineAccuracy, scores.UserNotificationQuality, scores.OverallQuality)
	t.Logf("Reasoning: %s", scores.Reasoning)

	threshold := 8
	dims := map[string]int{
		"regulatory_accuracy":       scores.RegulatoryAccuracy,
		"signal_transparency":       scores.SignalTransparency,
		"submission_honesty":        scores.SubmissionHonesty,
		"deadline_accuracy":         scores.DeadlineAccuracy,
		"user_notification_quality": scores.UserNotificationQuality,
		"overall_quality":           scores.OverallQuality,
	}
	for dim, score := range dims {
		if score < threshold {
			t.Errorf("%s: score %d < threshold %d", dim, score, threshold)
		}
	}
}
