//go:build cloudwalk

package cloud_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
)

// TestPrintKeys prints the walk installs' public keys for run.sh.
func TestPrintKeys(t *testing.T) {
	for i := range 5 {
		fmt.Println(base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(Seed(i)).Public().(ed25519.PublicKey)))
	}
}
