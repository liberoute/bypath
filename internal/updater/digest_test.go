package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleSHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func TestParseDigest(t *testing.T) {
	tests := []struct {
		name    string
		digest  string
		want    string
		wantErr bool
	}{
		{"valid", "sha256:" + sampleSHA, sampleSHA, false},
		{"uppercase", "SHA256:" + strings.ToUpper(sampleSHA), sampleSHA, false},
		{"surrounding space", "  sha256:" + sampleSHA + "\n", sampleSHA, false},
		{"missing prefix", sampleSHA, "", true},
		{"unsupported algorithm", "sha512:" + sampleSHA, "", true},
		{"too short", "sha256:abcd", "", true},
		{"not hex", "sha256:" + strings.Repeat("z", 64), "", true},
		{"empty", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDigest(tc.digest)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDigest(%q) succeeded, want error", tc.digest)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDigest(%q): %v", tc.digest, err)
			}
			if got != tc.want {
				t.Fatalf("ParseDigest(%q) = %q, want %q", tc.digest, got, tc.want)
			}
		})
	}
}

func TestVerifyFile(t *testing.T) {
	dir := t.TempDir()
	data := []byte("bypath release binary")
	path := filepath.Join(dir, "bypath")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	good := "sha256:" + hex.EncodeToString(sum[:])

	if err := VerifyFile(path, good); err != nil {
		t.Fatalf("VerifyFile with matching digest: %v", err)
	}

	bad := "sha256:" + strings.Repeat("0", 64)
	if err := VerifyFile(path, bad); err == nil {
		t.Fatal("VerifyFile with mismatched digest succeeded, want error")
	}
	if err := VerifyFile(path, "not-a-digest"); err == nil {
		t.Fatal("VerifyFile with malformed digest succeeded, want error")
	}
	if err := VerifyFile(filepath.Join(dir, "missing"), good); err == nil {
		t.Fatal("VerifyFile on missing file succeeded, want error")
	}
}
