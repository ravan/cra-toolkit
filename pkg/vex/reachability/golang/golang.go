// Package golang implements a reachability analyzer for Go using govulncheck.
package golang

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
)

// Analyzer uses govulncheck to determine reachability in Go projects.
type Analyzer struct{}

// New returns a new Go reachability analyzer.
func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Language() string { return "go" }

// govulncheckMessage represents a single JSON message in the govulncheck stream.
type govulncheckMessage struct {
	Finding *govulncheckFinding `json:"finding,omitempty"`
}

type govulncheckFinding struct {
	OSV          string             `json:"osv"`
	FixedVersion string             `json:"fixed_version"`
	Trace        []govulncheckFrame `json:"trace"`
}

type govulncheckFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
}

// Analyze runs govulncheck on the source directory and checks whether the
// vulnerability identified in the finding is reachable.
func (a *Analyzer) Analyze(ctx context.Context, sourceDir string, finding *formats.Finding) (reachability.Result, error) {
	output, err := runGovulncheck(ctx, sourceDir)
	if err != nil {
		return reachability.Result{}, fmt.Errorf("govulncheck: %w", err)
	}

	return ParseGovulncheckOutput(output, finding)
}

// runGovulncheck executes govulncheck -json ./... in the given directory.
func runGovulncheck(ctx context.Context, dir string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		// govulncheck exits non-zero when vulns are found; that's expected.
		if exitErr, ok := err.(*exec.ExitError); ok {
			_ = exitErr
			// Use whatever output was produced.
			if len(out) > 0 {
				return out, nil
			}
			return exitErr.Stderr, nil
		}
		return nil, err
	}
	return out, nil
}

// ParseGovulncheckOutput parses the govulncheck JSON stream and determines
// reachability for the given finding.
//
//nolint:gocognit,gocyclo // govulncheck output parsing has multiple finding levels
func ParseGovulncheckOutput(data []byte, finding *formats.Finding) (reachability.Result, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	scanner.Split(splitJSONObjects)

	moduleName := finding.AffectedName
	hasModuleFinding := false
	hasFunctionFinding := false
	var reachedFunctions []string

	for scanner.Scan() {
		var msg govulncheckMessage
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		if msg.Finding == nil {
			continue
		}

		// Check if any trace frame references the affected module.
		moduleMatched := false
		for _, frame := range msg.Finding.Trace {
			if matchesModule(frame.Module, moduleName) {
				moduleMatched = true
				break
			}
		}
		if !moduleMatched {
			continue
		}

		hasModuleFinding = true

		// The most detailed finding (with function in first frame) indicates called code.
		// govulncheck emits multiple findings per vuln with increasing detail:
		//   1. module-level (just module+version)
		//   2. package-level (module+version+package)
		//   3. symbol-level (module+version+package+function, with caller trace)
		if len(msg.Finding.Trace) > 0 && msg.Finding.Trace[0].Function != "" {
			hasFunctionFinding = true
			reachedFunctions = append(reachedFunctions, msg.Finding.Trace[0].Function)
		}
	}

	if !hasModuleFinding {
		// Module not in govulncheck output at all; not reachable by high confidence.
		return reachability.Result{
			Reachable:  false,
			Confidence: formats.ConfidenceHigh,
			Evidence:   fmt.Sprintf("govulncheck found no findings for module %s", moduleName),
		}, nil
	}

	if hasFunctionFinding {
		return reachability.Result{
			Reachable:  true,
			Confidence: formats.ConfidenceHigh,
			Evidence:   fmt.Sprintf("govulncheck confirmed function call(s) reachable: %s", strings.Join(reachedFunctions, ", ")),
			Symbols:    reachedFunctions,
		}, nil
	}

	// Module found but no function-level trace: imported but not called.
	return reachability.Result{
		Reachable:  false,
		Confidence: formats.ConfidenceHigh,
		Evidence:   fmt.Sprintf("govulncheck found module %s in dependencies but no vulnerable function is called", moduleName),
	}, nil
}

// matchesModule checks if the govulncheck module path matches the finding's
// affected name. The affected name might be a module path (e.g. "golang.org/x/text")
// or a package path.
func matchesModule(govulnModule, affectedName string) bool {
	return govulnModule == affectedName || strings.HasPrefix(affectedName, govulnModule+"/")
}

// splitJSONObjects is a bufio.SplitFunc that splits on top-level JSON objects
// by tracking brace depth.
//
//nolint:gocognit,gocyclo // JSON splitting state machine requires tracking multiple states
func splitJSONObjects(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading whitespace.
	start := 0
	for start < len(data) && (data[start] == ' ' || data[start] == '\n' || data[start] == '\r' || data[start] == '\t') {
		start++
	}
	if start >= len(data) {
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	}
	if data[start] != '{' {
		// Skip non-object data.
		start++
		return start, nil, nil
	}

	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(data); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch data[i] {
		case '\\':
			if inString {
				escaped = true
			}
		case '"':
			inString = !inString
		case '{':
			if !inString {
				depth++
			}
		case '}':
			if !inString {
				depth--
				if depth == 0 {
					return i + 1, data[start : i+1], nil
				}
			}
		}
	}

	if atEOF {
		return len(data), nil, nil
	}
	return 0, nil, nil
}
