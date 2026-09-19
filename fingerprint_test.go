package sql_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rqlite/sql"
)

func TestFingerprint(t *testing.T) {
	equivalent := []struct {
		name string
		sql  string
	}{
		{
			name: "whitespace-comments-and-keywords",
			sql:  "SELECT id FROM users /* keep */ WHERE active = 1",
		},
		{
			name: "compact",
			sql:  "select id from users where active=1;",
		},
		{
			name: "numeric-literal",
			sql:  "SELECT id FROM users WHERE active = 99999",
		},
		{
			name: "string-literal",
			sql:  "SELECT id FROM users WHERE name = 'changed secret' AND active = 1",
		},
	}

	base := mustFingerprintString(t, equivalent[0].sql)
	for i := 1; i < len(equivalent)-1; i++ {
		tc := equivalent[i]
		t.Run("Equivalent/"+tc.name, func(t *testing.T) {
			if got := mustFingerprintString(t, tc.sql); got != base {
				t.Fatalf("fingerprint = %s, want %s", got, base)
			}
		})
	}
	stringA := mustFingerprintString(t, "SELECT id FROM users WHERE name = 'a' AND active = 1")
	stringB := mustFingerprintString(t, equivalent[len(equivalent)-1].sql)
	if stringA != stringB {
		t.Fatalf("string literal content changed fingerprint")
	}
	blobA := mustFingerprintString(t, "SELECT x'01AB'")
	blobB := mustFingerprintString(t, "SELECT x'ff22'")
	if blobA != blobB {
		t.Fatalf("blob literal content changed fingerprint")
	}
	if blobA == stringA {
		t.Fatalf("blob literal was not distinguished from a string literal")
	}

	bindParams := []string{
		"INSERT INTO users(name, age) VALUES (?, ?)",
		"INSERT INTO users(name, age) VALUES (?1, ?2)",
		"INSERT INTO users(name, age) VALUES (:name, :age)",
		"INSERT INTO users(name, age) VALUES (@name, @age)",
		"INSERT INTO users(name, age) VALUES ($name, $age)",
	}
	for i, query := range bindParams[1:] {
		if got := mustFingerprintString(t, query); got != mustFingerprintString(t, bindParams[0]) {
			t.Fatalf("bind parameter case %d changed fingerprint", i+1)
		}
	}

	structural := []struct {
		name string
		sql  string
	}{
		{"table", "SELECT id FROM accounts WHERE active = 1"},
		{"column", "SELECT email FROM users WHERE active = 1"},
		{"operator", "SELECT id FROM users WHERE active < 1"},
		{"join-kind", "SELECT u.id FROM users u LEFT JOIN accounts a ON a.user_id = u.id"},
		{"join-constraint", "SELECT u.id FROM users u JOIN accounts a USING (id)"},
		{"subquery-shape", "SELECT id FROM users WHERE id IN (SELECT user_id FROM accounts WHERE active = 1)"},
		{"statement-type", "UPDATE users SET active = 1 WHERE id = 1"},
		{"insert-column", "INSERT INTO users(name) VALUES (?)"},
		{"update-from", "UPDATE users SET active = 1 FROM accounts WHERE accounts.user_id = users.id"},
		{"delete-returning", "DELETE FROM users WHERE id = 1 RETURNING id"},
		{"cte-name", "WITH recent AS (SELECT id FROM users) SELECT id FROM recent"},
		{"cte-shape", "WITH recent AS (SELECT id FROM accounts) SELECT id FROM recent"},
		{"window-function", "SELECT row_number() OVER (PARTITION BY tenant_id ORDER BY created_at) FROM users"},
		{"window-partition", "SELECT row_number() OVER (PARTITION BY account_id ORDER BY created_at) FROM users"},
		{"nested-subquery", "SELECT id FROM (SELECT id FROM (SELECT id FROM users)) AS u"},
	}
	seen := make(map[string]string)
	for _, tc := range structural {
		t.Run("Structural/"+tc.name, func(t *testing.T) {
			got := mustFingerprintString(t, tc.sql)
			if other, ok := seen[got]; ok {
				t.Fatalf("fingerprint collided with %s", other)
			}
			seen[got] = tc.name
		})
	}
}

func TestFingerprintQuotedIdentifiers(t *testing.T) {
	variants := []string{
		`SELECT User FROM Account`,
		`SELECT USER FROM ACCOUNT`,
		`SELECT "User" FROM "Account"`,
		`SELECT "USER" FROM "ACCOUNT"`,
	}
	base := mustFingerprintString(t, variants[0])
	for i, query := range variants[1:] {
		if got := mustFingerprintString(t, query); got != base {
			t.Fatalf("case-folded identifier case %d changed fingerprint", i+1)
		}
	}
	if identifier := mustFingerprintString(t, `SELECT 'User' FROM Account`); identifier == base {
		t.Fatalf("string literal was not distinguished from identifier")
	}
	if strings.Contains(strings.ToLower(base), "user") {
		t.Fatalf("identifier names must not be copied into the fingerprint")
	}
}

func TestFingerprintStatements(t *testing.T) {
	first, err := sql.FingerprintStatements("SELECT 1; INSERT INTO t VALUES (2)")
	if err != nil {
		t.Fatal(err)
	}
	second, err := sql.FingerprintStatements("SELECT 99 /* x */; INSERT INTO t VALUES (42)")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("got %d and %d fingerprints", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("statement %d fingerprint changed: %s != %s", i, first[i], second[i])
		}
	}

	reordered, err := sql.FingerprintStatements("INSERT INTO t VALUES (2); SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	if reordered[0] == first[0] || reordered[1] == first[1] {
		t.Fatalf("statement order was not preserved")
	}
}

func TestFingerprintParseError(t *testing.T) {
	fingerprints, err := sql.FingerprintStatements("SELECT 1; SELECT FROM")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if fingerprints != nil {
		t.Fatalf("expected no partial fingerprints, got %v", fingerprints)
	}
}

func TestFingerprintConcurrentAndImmutable(t *testing.T) {
	stmt, err := sql.NewParser(strings.NewReader("SELECT id FROM users WHERE id = ?")).ParseStatement()
	if err != nil {
		t.Fatal(err)
	}
	before := stmt.String()
	want := mustFingerprintString(t, "SELECT id FROM users WHERE id = ?42")

	const goroutines = 16
	const iterations = 20
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				got, err := sql.Fingerprint(stmt)
				if err != nil {
					errs <- err
					return
				}
				if got != want {
					errs <- fmt.Errorf("got %s, want %s", got, want)
					return
				}
				if stmt.String() != before {
					errs <- errors.New("fingerprint changed the AST")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func mustFingerprintString(t *testing.T, query string) string {
	t.Helper()
	fingerprint, err := sql.FingerprintString(query)
	if err != nil {
		t.Fatalf("FingerprintString(%q): %v", query, err)
	}
	if !strings.HasPrefix(fingerprint, sql.FingerprintVersionV1) {
		t.Fatalf("fingerprint %q lacks prefix %q", fingerprint, sql.FingerprintVersionV1)
	}
	return fingerprint
}
