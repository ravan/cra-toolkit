package policykit_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/policykit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSignature_CosignBundle(t *testing.T) {
	f, err := os.Open("../../testdata/policykit/cosign-bundle.json")
	require.NoError(t, err)
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only test file

	sig, err := policykit.ParseSignature(f, "cosign-bundle.json")
	require.NoError(t, err)

	assert.Equal(t, "cosign", sig.Format)
	assert.Equal(t, "cosign-bundle.json", sig.Path)
}

func TestParseSignature_UnknownFormat(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	r := bytes.NewReader(data)

	sig, err := policykit.ParseSignature(r, "random.bin")
	require.NoError(t, err)

	assert.Equal(t, "unknown", sig.Format)
	assert.Equal(t, "random.bin", sig.Path)
}
