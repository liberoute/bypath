package api

import "testing"

func TestSanitizeURIRejectsSSHKeyPath(t *testing.T) {
	if err := sanitizeURI("ssh://root@example.com:22?key=/root/.ssh/id_rsa#host"); err == nil {
		t.Fatal("sanitizeURI accepted a caller-supplied SSH key path")
	}
	if err := sanitizeURI("ssh://root@example.com:22#host"); err != nil {
		t.Fatalf("sanitizeURI rejected a password SSH link: %v", err)
	}
	if err := sanitizeURI("not a uri"); err != nil {
		t.Fatalf("sanitizeURI must leave parse errors to the service: %v", err)
	}
}
