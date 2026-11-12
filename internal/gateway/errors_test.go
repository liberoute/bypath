package gateway

import (
	"errors"
	"fmt"
	"testing"
)

func TestPermanentClassification(t *testing.T) {
	base := errors.New("no active link configured")
	wrapped := fmt.Errorf("starting engine: %w", permanent(base))
	if !IsPermanent(wrapped) {
		t.Fatal("permanent marker was lost through wrapping")
	}
	if !errors.Is(wrapped, base) {
		t.Fatal("permanent wrapper broke error identity")
	}
	if IsPermanent(errors.New("port already in use")) {
		t.Fatal("transient error classified as permanent")
	}
	if permanent(nil) != nil {
		t.Fatal("permanent(nil) must stay nil")
	}
}
