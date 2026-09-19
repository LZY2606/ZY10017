package sql

import (
	"errors"
	"testing"
)

type futureStatement struct{}

func (futureStatement) node()          {}
func (futureStatement) stmt()          {}
func (futureStatement) String() string { return "FUTURE" }

func TestFingerprintUnsupportedNode(t *testing.T) {
	_, err := Fingerprint(futureStatement{})
	if !errors.Is(err, ErrUnsupportedFingerprintNode) {
		t.Fatalf("error = %v, want ErrUnsupportedFingerprintNode", err)
	}
}
