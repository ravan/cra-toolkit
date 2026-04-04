package evidence

import (
	"bytes"
	"fmt"
	"os/exec"
)

// SignManifest attempts to Cosign-sign the manifest file.
// If cosign is not available or signing fails, returns an unsigned SignatureInfo.
func SignManifest(manifestPath, keyPath string) *SignatureInfo {
	cosignPath, err := exec.LookPath("cosign")
	if err != nil {
		return &SignatureInfo{
			Method:    "unsigned",
			Signature: "",
		}
	}

	var args []string
	if keyPath != "" {
		args = []string{"sign-blob", "--key", keyPath, "--bundle", manifestPath + ".sig", manifestPath}
	} else {
		args = []string{"sign-blob", "--yes", "--bundle", manifestPath + ".sig", manifestPath}
	}

	cmd := exec.Command(cosignPath, args...) //nolint:gosec // user-specified paths
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &SignatureInfo{
			Method:    "unsigned",
			Signature: fmt.Sprintf("signing failed: %v: %s", err, stderr.String()),
		}
	}

	method := "cosign-keyless"
	if keyPath != "" {
		method = "cosign-key"
	}

	return &SignatureInfo{
		Method:    method,
		Signature: manifestPath + ".sig",
	}
}
