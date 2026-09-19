package sql

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// fakeFingerprintStmt is a statement type the fingerprint format does not cover.
type fakeFingerprintStmt struct{}

func (fakeFingerprintStmt) node()          {}
func (fakeFingerprintStmt) stmt()          {}
func (fakeFingerprintStmt) String() string { return "FAKE" }

// fakeFingerprintExpr is an expression type the fingerprint format does not cover.
type fakeFingerprintExpr struct{}

func (fakeFingerprintExpr) node()          {}
func (fakeFingerprintExpr) expr()          {}
func (fakeFingerprintExpr) String() string { return "FAKE" }

// TestFingerprintUnhandledStatement verifies that an unknown statement type
// fails loudly with ErrFingerprintUnhandled instead of panicking or
// producing a fingerprint.
func TestFingerprintUnhandledStatement(t *testing.T) {
	fp, err := Fingerprint(fakeFingerprintStmt{})
	if !errors.Is(err, ErrFingerprintUnhandled) {
		t.Fatalf("Fingerprint() error = %v, want ErrFingerprintUnhandled", err)
	}
	if fp != "" {
		t.Fatalf("Fingerprint() returned %q, want no fingerprint on error", fp)
	}
}

// TestFingerprintUnhandledNode verifies that an unknown interior node type
// fails loudly with ErrFingerprintUnhandled.
func TestFingerprintUnhandledNode(t *testing.T) {
	stmt := &SelectStatement{
		Columns: []*ResultColumn{{Expr: fakeFingerprintExpr{}}},
	}
	v := &fingerprintVisitor{h: sha256.New()}
	if _, err := Walk(v, stmt); !errors.Is(err, ErrFingerprintUnhandled) {
		t.Fatalf("Walk() error = %v, want ErrFingerprintUnhandled", err)
	}
}

// TestFingerprintNilStatement verifies that a nil statement is rejected.
func TestFingerprintNilStatement(t *testing.T) {
	if _, err := Fingerprint(nil); err == nil {
		t.Fatal("Fingerprint(nil) expected error, got nil")
	}
}

// TestFingerprintDoesNotMutateAST verifies, at the node level, that
// fingerprinting leaves every position and value of the source AST intact.
func TestFingerprintDoesNotMutateAST(t *testing.T) {
	const input = `WITH c(x) AS (SELECT a FROM u WHERE b = 'lit') SELECT "Q", q FROM t JOIN c ON t.id = c.x WHERE t.n IN (SELECT n FROM v) ORDER BY q DESC LIMIT 5`
	stmt, err := NewParser(strings.NewReader(input)).ParseStatement()
	if err != nil {
		t.Fatalf("ParseStatement() error: %v", err)
	}
	before := stmt.String()
	if _, err := Fingerprint(stmt); err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}
	if after := stmt.String(); after != before {
		t.Fatalf("statement modified:\n  before: %s\n  after:  %s", before, after)
	}
}
