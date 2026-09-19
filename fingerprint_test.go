package sql_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/rqlite/sql"
)

// TestFingerprintEquivalent verifies that statements differing only in
// whitespace, comments, literal contents, bind parameter names or unquoted
// identifier case share the same fingerprint.
func TestFingerprintEquivalent(t *testing.T) {
	groups := map[string][]string{
		"WhitespaceAndComments": {
			"SELECT a FROM t",
			"SELECT  a\nFROM   t",
			"SELECT a /* inline */ FROM t -- trailing",
			"  SELECT a FROM t  ",
		},
		"NumberLiterals": {
			"SELECT * FROM t WHERE a = 1",
			"SELECT * FROM t WHERE a = 9999",
			"SELECT * FROM t WHERE a = 1.5e3",
		},
		"StringLiterals": {
			"SELECT * FROM t WHERE name = 'alice'",
			"SELECT * FROM t WHERE name = 'bob'",
			"SELECT * FROM t WHERE name = 'it''s'",
		},
		"BlobLiterals": {
			"SELECT * FROM t WHERE b = x'01'",
			"SELECT * FROM t WHERE b = x'ff00'",
		},
		"BindParameters": {
			"SELECT * FROM t WHERE a = ?",
			"SELECT * FROM t WHERE a = ?1",
			"SELECT * FROM t WHERE a = :alpha",
			"SELECT * FROM t WHERE a = @beta",
			"SELECT * FROM t WHERE a = $gamma",
		},
		"UnquotedIdentifierCase": {
			"SELECT A, b FROM T WHERE C = 1",
			"select a, B from t where c = 2",
		},
		"Insert": {
			"INSERT INTO t (a, b) VALUES (1, 'x')",
			"insert into t(a,b) values(2,'y')",
		},
		"InsertBindParameters": {
			"INSERT INTO t (a, b) VALUES (?, ?)",
			"INSERT INTO t (a, b) VALUES (?1, ?2)",
			"INSERT INTO t (a, b) VALUES (:x, :y)",
		},
		"InsertMultiRow": {
			"INSERT INTO t VALUES (1), (2), (3)",
			"INSERT INTO t VALUES (10), (20), (30)",
		},
		"UpdateFrom": {
			"UPDATE t SET a = 1 FROM u WHERE t.id = u.id",
			"UPDATE t SET a = 99 FROM u WHERE t.id = u.id",
		},
		"DeleteReturning": {
			"DELETE FROM t WHERE id = 1 RETURNING id",
			"DELETE FROM t WHERE id = 42 RETURNING id",
		},
		"CTE": {
			"WITH c AS (SELECT 1) SELECT * FROM c",
			"WITH c AS (SELECT 2) SELECT * FROM c",
		},
		"WindowFrameLiterals": {
			"SELECT sum(a) OVER (ORDER BY b ROWS BETWEEN 1 PRECEDING AND 2 FOLLOWING) FROM t",
			"SELECT sum(a) OVER (ORDER BY b ROWS BETWEEN 5 PRECEDING AND 99 FOLLOWING) FROM t",
		},
		"NestedSubqueries": {
			"SELECT * FROM t WHERE a IN (SELECT b FROM u WHERE c = (SELECT max(d) FROM v WHERE e = 1))",
			"SELECT * FROM t WHERE a IN (SELECT b FROM u WHERE c = (SELECT max(d) FROM v WHERE e = 2))",
		},
		"LimitLiteral": {
			"SELECT * FROM t LIMIT 10",
			"SELECT * FROM t LIMIT 20",
		},
	}

	for name, stmts := range groups {
		t.Run(name, func(t *testing.T) {
			var want string
			for i, s := range stmts {
				fps, err := sql.FingerprintString(s)
				if err != nil {
					t.Fatalf("FingerprintString(%q) error: %v", s, err)
				}
				if len(fps) != 1 {
					t.Fatalf("FingerprintString(%q) returned %d fingerprints, want 1", s, len(fps))
				}
				if i == 0 {
					want = fps[0]
				} else if fps[0] != want {
					t.Errorf("fingerprint mismatch:\n  %q -> %s\n  %q -> %s", stmts[0], want, s, fps[0])
				}
			}
		})
	}
}

// TestFingerprintDistinct verifies that structural changes always change
// the fingerprint.
func TestFingerprintDistinct(t *testing.T) {
	pairs := map[string][2]string{
		"ColumnName":        {"SELECT a FROM t", "SELECT b FROM t"},
		"TableName":         {"SELECT a FROM t", "SELECT a FROM u"},
		"Operator":          {"SELECT * FROM t WHERE b = 1", "SELECT * FROM t WHERE b < 1"},
		"UnaryOperator":     {"SELECT -a FROM t", "SELECT ~a FROM t"},
		"JoinKind":          {"SELECT * FROM a JOIN b ON a.x = b.x", "SELECT * FROM a LEFT JOIN b ON a.x = b.x"},
		"JoinOperator":      {"SELECT * FROM a, b", "SELECT * FROM a CROSS JOIN b"},
		"ExtraCondition":    {"SELECT * FROM t WHERE a = 1", "SELECT * FROM t WHERE a = 1 AND b = 2"},
		"SubqueryStructure": {"SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u)", "SELECT * FROM t WHERE a IN (SELECT b FROM u)"},
		"NestedSubquery":    {"SELECT * FROM t WHERE a = (SELECT max(b) FROM u)", "SELECT * FROM t WHERE a = (SELECT max(b) FROM u WHERE c = 1)"},
		"StatementType":     {"SELECT a FROM t", "DELETE FROM t"},
		"QuotedIdentCase":   {`SELECT "Foo" FROM t`, `SELECT "foo" FROM t`},
		"QuotedVsUnquoted":  {`SELECT "Foo" FROM t`, `SELECT Foo FROM t`},
		"Alias":             {"SELECT a FROM t", "SELECT a AS b FROM t"},
		"DistinctVsAll":     {"SELECT DISTINCT a FROM t", "SELECT ALL a FROM t"},
		"SortDirection":     {"SELECT * FROM t ORDER BY a ASC", "SELECT * FROM t ORDER BY a DESC"},
		"InsertOrAction":    {"INSERT INTO t VALUES (1)", "INSERT OR IGNORE INTO t VALUES (1)"},
		"CTEName":           {"WITH c AS (SELECT 1) SELECT * FROM c", "WITH d AS (SELECT 1) SELECT * FROM d"},
		"CTEBody":           {"WITH c AS (SELECT a FROM t) SELECT * FROM c", "WITH c AS (SELECT a FROM u) SELECT * FROM c"},
		"WindowPartition":   {"SELECT sum(a) OVER (PARTITION BY b) FROM t", "SELECT sum(a) OVER (ORDER BY b) FROM t"},
		"WindowFrameMode":   {"SELECT sum(a) OVER (ROWS UNBOUNDED PRECEDING) FROM t", "SELECT sum(a) OVER (RANGE UNBOUNDED PRECEDING) FROM t"},
		"UpdateFromClause":  {"UPDATE t SET a = 1", "UPDATE t SET a = 1 FROM u"},
		"DeleteReturning":   {"DELETE FROM t WHERE id = 1", "DELETE FROM t WHERE id = 1 RETURNING id"},
		"CompoundKind":      {"SELECT a FROM t UNION SELECT a FROM u", "SELECT a FROM t UNION ALL SELECT a FROM u"},
		"NullCheck":         {"SELECT * FROM t WHERE a IS NULL", "SELECT * FROM t WHERE a IS NOT NULL"},
		"GroupBy":           {"SELECT * FROM t GROUP BY a", "SELECT * FROM t GROUP BY a, b"},
		"CastType":          {"SELECT CAST(a AS INTEGER) FROM t", "SELECT CAST(a AS TEXT) FROM t"},
		"BoolLiteral":       {"SELECT TRUE", "SELECT FALSE"},
		"LiteralKind":       {"SELECT * FROM t WHERE a = 1", "SELECT * FROM t WHERE a = '1'"},
		"CreateTableType":   {"CREATE TABLE t (a INTEGER)", "CREATE TABLE t (a TEXT)"},
		"ParenStructure":    {"SELECT * FROM t WHERE a = 1 AND (b = 2 OR c = 3)", "SELECT * FROM t WHERE (a = 1 AND b = 2) OR c = 3"},
	}

	for name, pair := range pairs {
		t.Run(name, func(t *testing.T) {
			fp0 := mustFingerprintString(t, pair[0])
			fp1 := mustFingerprintString(t, pair[1])
			if fp0 == fp1 {
				t.Errorf("expected distinct fingerprints:\n  %q -> %s\n  %q -> %s", pair[0], fp0, pair[1], fp1)
			}
		})
	}
}

// TestFingerprintMultiStatement verifies that multi-statement input yields
// one fingerprint per statement, in order.
func TestFingerprintMultiStatement(t *testing.T) {
	const input = "SELECT a FROM t WHERE id = 1; INSERT INTO t VALUES (2); DELETE FROM t RETURNING id"
	fps, err := sql.FingerprintString(input)
	if err != nil {
		t.Fatalf("FingerprintString() error: %v", err)
	}
	if len(fps) != 3 {
		t.Fatalf("FingerprintString() returned %d fingerprints, want 3", len(fps))
	}

	// Each fingerprint must match the fingerprint of the statement parsed on
	// its own, proving order is preserved.
	individual := []string{
		"SELECT a FROM t WHERE id = 999",
		"INSERT INTO t VALUES (999) /* comment */",
		"delete from t returning id",
	}
	for i, s := range individual {
		if got := mustFingerprintString(t, s); got != fps[i] {
			t.Errorf("statement %d: fingerprint %s does not match individual fingerprint %s", i, fps[i], got)
		}
	}

	// Reordering statements must reorder the fingerprints.
	rev, err := sql.FingerprintString("DELETE FROM t RETURNING id; INSERT INTO t VALUES (2); SELECT a FROM t WHERE id = 1")
	if err != nil {
		t.Fatalf("FingerprintString() error: %v", err)
	}
	if rev[0] != fps[2] || rev[1] != fps[1] || rev[2] != fps[0] {
		t.Errorf("reordered input did not produce reordered fingerprints")
	}
}

// TestFingerprintParseError verifies that a parse failure returns the parse
// error and no partial results.
func TestFingerprintParseError(t *testing.T) {
	for _, input := range []string{
		"SELECT * FROM",
		"SELECT 1; THIS IS NOT SQL",
		"SELECT 1; INSERT INTO t VALUES (1); GARBAGE (",
	} {
		fps, err := sql.FingerprintString(input)
		if err == nil {
			t.Errorf("FingerprintString(%q): expected error, got nil", input)
		}
		if fps != nil {
			t.Errorf("FingerprintString(%q): expected nil fingerprints on error, got %v", input, fps)
		}
	}
}

// TestFingerprintConcurrent verifies that concurrent fingerprinting of the
// same AST yields identical results and does not modify the AST.
func TestFingerprintConcurrent(t *testing.T) {
	stmt, err := sql.NewParser(strings.NewReader(
		`WITH c AS (SELECT max(a) AS m FROM u WHERE z > 10)
		 SELECT row_number() OVER w, t.id, c.m
		 FROM t LEFT JOIN c ON c.m = t.id
		 WHERE t.id IN (SELECT id FROM u WHERE u.q = ?)
		 WINDOW w AS (PARTITION BY t.x ORDER BY t.y ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
		 ORDER BY t.id DESC LIMIT 100`,
	)).ParseStatement()
	if err != nil {
		t.Fatalf("ParseStatement() error: %v", err)
	}

	before := stmt.String()
	want, err := sql.Fingerprint(stmt)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}

	const goroutines = 32
	const iterations = 50
	errs := make(chan error, goroutines*iterations)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				fp, err := sql.Fingerprint(stmt)
				if err != nil {
					errs <- err
					return
				}
				if fp != want {
					errs <- fmt.Errorf("concurrent fingerprint %s != %s", fp, want)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	if after := stmt.String(); after != before {
		t.Errorf("statement modified by Fingerprint():\n  before: %s\n  after:  %s", before, after)
	}
}

// TestFingerprintVersionPrefix verifies that fingerprints carry the version
// prefix.
func TestFingerprintVersionPrefix(t *testing.T) {
	fp := mustFingerprintString(t, "SELECT 1")
	if !strings.HasPrefix(fp, sql.FingerprintVersion+":") {
		t.Errorf("fingerprint %q missing version prefix %q", fp, sql.FingerprintVersion+":")
	}
	if rest := strings.TrimPrefix(fp, sql.FingerprintVersion+":"); len(rest) != 32 {
		t.Errorf("fingerprint digest %q has length %d, want 32 hex characters", rest, len(rest))
	}
}

// TestFingerprintStability verifies that repeated runs over the same input
// produce identical fingerprints.
func TestFingerprintStability(t *testing.T) {
	const input = "UPDATE t SET a = 1 FROM u WHERE t.id = u.id RETURNING a"
	first := mustFingerprintString(t, input)
	for i := 0; i < 100; i++ {
		if got := mustFingerprintString(t, input); got != first {
			t.Fatalf("iteration %d: fingerprint %s != %s", i, got, first)
		}
	}
}

func mustFingerprintString(t *testing.T, s string) string {
	t.Helper()
	fps, err := sql.FingerprintString(s)
	if err != nil {
		t.Fatalf("FingerprintString(%q) error: %v", s, err)
	}
	if len(fps) != 1 {
		t.Fatalf("FingerprintString(%q) returned %d fingerprints, want 1", s, len(fps))
	}
	return fps[0]
}

// ExampleFingerprint demonstrates computing the structural fingerprint of a
// single parsed statement.
func ExampleFingerprint() {
	stmt, err := sql.NewParser(strings.NewReader("SELECT * FROM users WHERE id = 123")).ParseStatement()
	if err != nil {
		panic(err)
	}
	fp, err := sql.Fingerprint(stmt)
	if err != nil {
		panic(err)
	}
	fmt.Println(strings.HasPrefix(fp, sql.FingerprintVersion+":"))
	// Output: true
}

// ExampleFingerprintString demonstrates fingerprinting multi-statement
// input: literal contents do not affect the fingerprints.
func ExampleFingerprintString() {
	fps, err := sql.FingerprintString("SELECT * FROM users WHERE id = 1; SELECT * FROM users WHERE id = 2")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(fps))
	fmt.Println(fps[0] == fps[1])
	// Output:
	// 2
	// true
}
